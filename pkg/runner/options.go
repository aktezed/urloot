package runner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/aktezed/urloot/pkg/types"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// ParseOptions parses CLI flags and subcommands into a validated Options struct.
func ParseOptions() *types.Options {
	opts := &types.Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("urloot - passive & active URL harvester, normalizer, and SQLite endpoint differ")

	if configDir, err := os.UserConfigDir(); err == nil {
		appDir := filepath.Join(configDir, "urloot")
		if err := os.MkdirAll(appDir, 0o755); err == nil {
			targetConfig := filepath.Join(appDir, "config.yaml")
			if f, err := os.OpenFile(targetConfig, os.O_RDWR|os.O_CREATE, 0o644); err == nil {
				_ = f.Close()
				flagSet.SetConfigFilePath(targetConfig)
			}
		}
	}

	args := normalizeCLIArgs(os.Args[1:])
	if len(args) > 0 {
		switch args[0] {
		case "scan":
			opts.Command = "scan"
			args = args[1:]
		case "query":
			opts.Command = "query"
			opts.Query = true
			args = args[1:]
		}
	}

	// Input
	flagSet.CreateGroup("input", "INPUT",
		flagSet.StringVarP(&opts.Domain, "domain", "d", "", "target domain or subdomain to harvest (e.g. example.com)"),
		flagSet.StringVarP(&opts.List, "list", "l", "", "file containing target domains, hosts, or URLs (one per line)"),
		flagSet.StringVar(&opts.Scope, "scope", "", "restrict crawl and harvest to root domain (default: auto eTLD+1)"),
		flagSet.StringSliceVar(&opts.Exclude, "exclude", nil, "comma-separated hosts or path prefixes to exclude", goflags.CommaSeparatedStringSliceOptions),
	)

	// Passive Archives
	flagSet.CreateGroup("passive", "PASSIVE ARCHIVES (GAU ENGINE)",
		flagSet.BoolVar(&opts.NoPassive, "no-passive", false, "disable passive archive harvesting"),
		flagSet.StringSliceVar(&opts.Providers, "providers", []string{"wayback", "commoncrawl", "otx", "urlscan"}, "passive providers to query", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVar(&opts.IncludeSubs, "subs", true, "include subdomains when querying passive archives"),
		flagSet.IntVar(&opts.ArchiveTimeout, "archive-timeout", 20, "per-provider HTTP timeout in seconds"),
		flagSet.StringVar(&opts.OTXKey, "otx-key", "", "optional AlienVault OTX API key"),
		flagSet.StringVar(&opts.URLScanKey, "urlscan-key", "", "optional URLScan.io API key"),
	)

	// Active Crawler
	flagSet.CreateGroup("active", "ACTIVE CRAWLER (KATANA ENGINE)",
		flagSet.BoolVar(&opts.NoActive, "no-active", false, "disable active live web spidering"),
		flagSet.IntVarP(&opts.Concurrency, "concurrency", "c", 10, "concurrent spidering workers"),
		flagSet.IntVar(&opts.RateLimit, "rate", 30, "global maximum active HTTP requests per second"),
		flagSet.IntVar(&opts.Depth, "depth", 3, "maximum active crawl depth"),
		flagSet.IntVar(&opts.Timeout, "timeout", 10, "per-request active crawl timeout in seconds"),
		flagSet.BoolVar(&opts.ParseJS, "js", true, "parse and extract endpoints from <script src> JS bundles"),
		flagSet.StringSliceVarP(&opts.Headers, "headers", "H", nil, "custom HTTP headers (e.g. 'Cookie: sid=1')", goflags.StringSliceOptions),
		flagSet.StringVar(&opts.Proxy, "proxy", "", "HTTP/SOCKS5 proxy URL for active crawling"),
	)

	// Normalizer
	flagSet.CreateGroup("normalizer", "NORMALIZER (URO ENGINE)",
		flagSet.BoolVar(&opts.NoNormalize, "no-norm", false, "disable path/parameter collapsing"),
		flagSet.BoolVar(&opts.KeepStatic, "keep-static", false, "retain static media, font, and stylesheet URLs"),
		flagSet.StringSliceVar(&opts.BlacklistExt, "blacklist-ext", nil, "additional file extensions to prune", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&opts.KeepExt, "keep-ext", nil, "file extensions to exempt from pruning", goflags.CommaSeparatedStringSliceOptions),
	)

	// Storage & Query
	flagSet.CreateGroup("storage", "STORAGE & QUERY (SQLITE)",
		flagSet.StringVar(&opts.DBPath, "db", "", "SQLite database path (default: <domain>.db or urloot.db)"),
		flagSet.BoolVar(&opts.NoDB, "no-db", false, "run in-memory without writing a SQLite database"),
		flagSet.BoolVarP(&opts.Query, "query", "q", false, "run in query mode against an existing SQLite database"),
		flagSet.BoolVarP(&opts.NewOnly, "new-only", "new", false, "output only endpoints/URLs first discovered in the latest scan"),
		flagSet.StringVarP(&opts.Target, "target", "t", "", "filter query by root domain"),
		flagSet.StringVar(&opts.Host, "host", "", "filter query by exact hostname"),
		flagSet.StringVar(&opts.Path, "path", "", "filter query by normalized endpoint path substring"),
		flagSet.BoolVar(&opts.HasParams, "has-params", false, "only URLs containing query parameters"),
		flagSet.StringSliceVar(&opts.Params, "param", nil, "filter by parameter name (comma-separated OR)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&opts.ParamType, "param-type", nil, "filter by parameter value class (int,uuid,hash,url_or_path,str)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&opts.Sources, "source", nil, "filter by discovery source (wayback,commoncrawl,otx,urlscan,katana)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVar(&opts.Ext, "ext", nil, "filter by file extension (e.g. php,json,aspx)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVar(&opts.Status, "status", "", "filter by HTTP status codes (e.g. 200,403)"),
		flagSet.StringVar(&opts.RawSQL, "sql", "", "execute raw read-only SQL query against the database"),
	)

	defaultOutFormat := "table"
	if isStdoutPiped() {
		defaultOutFormat = "list"
	}

	// Output & General
	flagSet.CreateGroup("output", "OUTPUT & GENERAL",
		flagSet.StringVarP(&opts.OutputFormat, "output-format", "o", defaultOutFormat, "output format: list, json, table"),
		flagSet.StringVar(&opts.OutputFile, "out", "", "write output to file path in addition to STDOUT"),
		flagSet.BoolVarP(&opts.Silent, "silent", "s", false, "silent mode: suppress banner and progress logs"),
		flagSet.BoolVar(&opts.Version, "version", false, "show urloot version"),
	)

	if err := flagSet.Parse(args...); err != nil {
		gologger.Fatal().Msgf("Could not parse flags: %s\n", err)
	}

	if opts.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	if opts.Version {
		showBanner()
		os.Exit(0)
	}

	if !opts.Silent {
		showBanner()
	}

	if err := validateOptions(opts); err != nil {
		gologger.Fatal().Msgf("Options error: %s\n", err)
	}

	return opts
}

func validateOptions(opts *types.Options) error {
	if opts.Query {
		opts.Command = "query"
	} else if opts.Command == "" {
		opts.Command = "scan"
	}

	opts.OutputFormat = strings.ToLower(strings.TrimSpace(opts.OutputFormat))
	if opts.OutputFormat == "" {
		opts.OutputFormat = "table"
	}
	switch opts.OutputFormat {
	case "list", "json", "table":
	default:
		return errors.New("invalid -o / -output-format: must be list, json, or table")
	}

	if opts.Command == "query" {
		if opts.DBPath == "" && opts.Domain != "" {
			opts.DBPath = opts.Domain + ".db"
		}
		if opts.DBPath == "" && opts.Target != "" {
			opts.DBPath = opts.Target + ".db"
		}
		if opts.DBPath == "" {
			opts.DBPath = "urloot.db"
		}
		return nil
	}

	if opts.NoPassive && opts.NoActive {
		return errors.New("cannot specify both -no-passive and -no-active")
	}

	if opts.Domain == "" && opts.List == "" && len(opts.Targets) == 0 && !hasStdin() {
		return errors.New("no target specified: provide -d <domain>, -l <file>, or pipe targets via STDIN")
	}

	return nil
}

func normalizeCLIArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "--new-only" || a == "-new-only" || a == "--new" {
			out[i] = "-new"
			continue
		}
		out[i] = a
	}
	return out
}

func hasStdin() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}

func isStdoutPiped() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}
