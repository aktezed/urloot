package runner

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/aktezed/urloot/pkg/archive"
	"github.com/aktezed/urloot/pkg/crawler"
	"github.com/aktezed/urloot/pkg/normalizer"
	"github.com/aktezed/urloot/pkg/store"
	"github.com/aktezed/urloot/pkg/types"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/publicsuffix"
)

// Runner coordinates target ingestion, passive archive harvesting, active spidering,
// URL normalization, SQLite persistence, and CLI query/output formatting.
type Runner struct {
	options   *types.Options
	store     *store.Store
	harvester *archive.Harvester
	crawler   *crawler.Crawler
	outWriter io.Writer
}

// NewRunner constructs a Runner using manual constructor injection.
func NewRunner(options *types.Options) (*Runner, error) {
	if options == nil {
		return nil, errors.New("options cannot be nil")
	}
	if options.Command == "" {
		if options.Query {
			options.Command = "query"
		} else {
			options.Command = "scan"
		}
	}
	if options.OutputFormat == "" {
		options.OutputFormat = "table"
	}
	return &Runner{
		options:   options,
		outWriter: os.Stdout,
	}, nil
}

// SetOutput overrides the destination writer (default os.Stdout), useful for SDK consumers and tests.
func (r *Runner) SetOutput(w io.Writer) {
	if w != nil {
		r.outWriter = w
	}
}

// SetHarvester injects a custom archive.Harvester (used in integration tests).
func (r *Runner) SetHarvester(h *archive.Harvester) {
	r.harvester = h
}

// SetCrawler injects a custom crawler.Crawler (used in integration tests).
func (r *Runner) SetCrawler(c *crawler.Crawler) {
	r.crawler = c
}

// Close closes any open SQLite database connection.
func (r *Runner) Close() error {
	if r.store != nil {
		return r.store.Close()
	}
	return nil
}

// Run dispatches execution to either ExecuteScan or ExecuteQuery.
func (r *Runner) Run(ctx context.Context) error {
	switch r.options.Command {
	case "scan":
		return r.ExecuteScan(ctx)
	case "query":
		return r.ExecuteQuery(ctx)
	default:
		return fmt.Errorf("unknown command %q", r.options.Command)
	}
}

// ExecuteScan runs the full ingestion -> passive + active collection -> normalizer -> SQLite pipeline.
func (r *Runner) ExecuteScan(ctx context.Context) error {
	seeds, domains, roots, err := r.ingestTargets()
	if err != nil {
		return err
	}

	destWriter, closeFile, err := r.prepareOutputWriter()
	if err != nil {
		return err
	}
	defer closeFile()

	dbPath := r.resolveDBPath(roots)
	var scanID int64
	if !r.options.NoDB {
		st, err := store.New(dbPath, false)
		if err != nil {
			return fmt.Errorf("open sqlite store: %w", err)
		}
		r.store = st
		optsJSON, _ := json.Marshal(r.options)
		scanID, err = st.BeginScan(roots, string(optsJSON))
		if err != nil {
			return fmt.Errorf("begin scan: %w", err)
		}
	}

	scopeRoot := r.options.Scope
	if scopeRoot == "" && len(roots) == 1 {
		scopeRoot = roots[0]
	}

	norm := normalizer.New(normalizer.Config{
		NoNormalize:  r.options.NoNormalize,
		KeepStatic:   r.options.KeepStatic,
		BlacklistExt: r.options.BlacklistExt,
		KeepExt:      r.options.KeepExt,
		ScopeRoot:    scopeRoot,
		Exclude:      r.options.Exclude,
	})

	rawChan := make(chan types.RawURL, 1024)
	var collectorWG sync.WaitGroup

	// 1. Passive Archive Harvester (GAU Engine)
	if !r.options.NoPassive && len(domains) > 0 {
		harv := r.harvester
		if harv == nil {
			harv = archive.NewHarvester(archive.Config{
				Providers:  r.options.Providers,
				Timeout:    time.Duration(r.options.ArchiveTimeout) * time.Second,
				OTXKey:     r.options.OTXKey,
				URLScanKey: r.options.URLScanKey,
			})
		}
		for _, d := range domains {
			collectorWG.Go(func() {
				if !r.options.Silent {
					gologger.Info().Msgf("Harvesting passive archives for %s\n", d)
				}
				harv.Harvest(ctx, d, r.options.IncludeSubs, rawChan)
			})
		}
	}

	// 2. Active Spidering Engine (Katana Engine)
	if !r.options.NoActive && len(seeds) > 0 {
		cr := r.crawler
		if cr == nil {
			cr, err = crawler.New(crawler.Config{
				Concurrency: r.options.Concurrency,
				RateLimit:   r.options.RateLimit,
				MaxDepth:    r.options.Depth,
				Timeout:     time.Duration(r.options.Timeout) * time.Second,
				ParseJS:     r.options.ParseJS,
				Headers:     r.options.Headers,
				Proxy:       r.options.Proxy,
				ScopeRoot:   scopeRoot,
				Exclude:     r.options.Exclude,
			})
			if err != nil {
				return fmt.Errorf("init active crawler: %w", err)
			}
		}
		collectorWG.Go(func() {
			if !r.options.Silent {
				gologger.Info().Msgf("Spidering %d live seed target(s) (depth=%d, rate=%d req/s)\n",
					len(seeds), max(r.options.Depth, 3), max(r.options.RateLimit, 30))
			}
			cr.Crawl(ctx, seeds, rawChan)
		})
	}

	go func() {
		collectorWG.Wait()
		close(rawChan)
	}()

	var rawCount atomic.Int64
	streamImmediate := r.options.NoDB && (r.options.OutputFormat == "list" || r.options.OutputFormat == "json")

	for raw := range rawChan {
		rawCount.Add(1)
		item, isFirstInSession := norm.Process(raw)
		if !isFirstInSession || item == nil {
			continue
		}
		if streamImmediate {
			_ = WriteOutput(destWriter, r.options.OutputFormat, []types.NormalizedURL{*item}, nil, "")
		}
	}

	// shortcut: buffers session-unique URLs in memory before 500-row SQLite batch flush, switch to streaming chunk flushes if a single target exceeds 5M unique normalized routes
	records := norm.Records()
	newCount := len(records)

	if r.store != nil {
		// Persist in batches of 500 records
		const batchSize = 500
		newCount = 0
		for i := 0; i < len(records); i += batchSize {
			end := min(i+batchSize, len(records))
			n, err := r.store.BatchUpsert(scanID, records[i:end])
			if err != nil {
				return fmt.Errorf("sqlite batch upsert: %w", err)
			}
			newCount += n
		}
		_ = r.store.FinishScan(scanID, int(rawCount.Load()), len(records), newCount)

		if !r.options.Silent {
			gologger.Info().Msgf("Saved %d deduplicated endpoints (%d new) to %s (from %d raw URLs)\n",
				len(records), newCount, dbPath, rawCount.Load())
		}

		// Query back from SQLite so source merges, status codes, and filters (--new-only) are consistent
		queryOpts := &types.Options{
			NewOnly:   r.options.NewOnly,
			HasParams: r.options.HasParams,
			Params:    r.options.Params,
			ParamType: r.options.ParamType,
			Sources:   r.options.Sources,
			Ext:       r.options.Ext,
			Status:    r.options.Status,
			Host:      r.options.Host,
			Path:      r.options.Path,
		}
		dbURLs, err := r.store.QueryURLs(queryOpts)
		if err != nil {
			return err
		}
		var dbParams []types.ParamRecord
		if r.options.OutputFormat == "table" {
			dbParams, _ = r.store.QueryParams("", r.options.NewOnly)
		}
		return WriteOutput(destWriter, r.options.OutputFormat, dbURLs, dbParams, strings.Join(roots, ", "))
	}

	if streamImmediate {
		return nil
	}

	outSlice := make([]types.NormalizedURL, 0, len(records))
	for _, rec := range records {
		if r.options.NewOnly && !rec.IsNew {
			continue
		}
		outSlice = append(outSlice, *rec)
	}
	return WriteOutput(destWriter, r.options.OutputFormat, outSlice, nil, strings.Join(roots, ", "))
}

// ExecuteQuery runs read-only filtered queries or custom SQL against an existing SQLite database.
func (r *Runner) ExecuteQuery(_ context.Context) error {
	dbPath := r.options.DBPath
	if dbPath == "" {
		dbPath = "urloot.db"
	}

	destWriter, closeFile, err := r.prepareOutputWriter()
	if err != nil {
		return err
	}
	defer closeFile()

	if strings.TrimSpace(r.options.RawSQL) != "" {
		cols, rows, err := store.RunRawSQL(dbPath, r.options.RawSQL)
		if err != nil {
			return fmt.Errorf("raw sql error: %w", err)
		}
		tw := tabwriter.NewWriter(destWriter, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, strings.Join(cols, "\t"))
		for _, row := range rows {
			fmt.Fprintln(tw, strings.Join(row, "\t"))
		}
		return tw.Flush()
	}

	st, err := store.New(dbPath, true)
	if err != nil {
		return err
	}
	r.store = st

	urls, err := st.QueryURLs(r.options)
	if err != nil {
		return err
	}
	var params []types.ParamRecord
	if r.options.OutputFormat == "table" {
		params, _ = st.QueryParams(r.options.Target, r.options.NewOnly)
	}

	label := cmp.Or(r.options.Target, dbPath)
	return WriteOutput(destWriter, r.options.OutputFormat, urls, params, label)
}

func (r *Runner) ingestTargets() (seeds []string, domains []string, roots []string, err error) {
	var rawInputs []string

	if d := strings.TrimSpace(r.options.Domain); d != "" {
		rawInputs = append(rawInputs, d)
	}
	rawInputs = append(rawInputs, r.options.Targets...)

	if listPath := strings.TrimSpace(r.options.List); listPath != "" {
		f, err := os.Open(listPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("open target list %q: %w", listPath, err)
		}
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				rawInputs = append(rawInputs, line)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, nil, nil, err
		}
	}

	if len(rawInputs) == 0 && hasStdin() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				rawInputs = append(rawInputs, line)
			}
		}
	}

	seedSeen := make(map[string]struct{})
	domSeen := make(map[string]struct{})
	rootSeen := make(map[string]struct{})

	for _, item := range rawInputs {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		seedURL := item
		if !strings.HasPrefix(strings.ToLower(seedURL), "http://") && !strings.HasPrefix(strings.ToLower(seedURL), "https://") {
			seedURL = "https://" + strings.TrimPrefix(seedURL, "//")
		}
		u, err := url.Parse(seedURL)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		host = strings.TrimPrefix(host, "*.")
		host = strings.TrimSuffix(host, ".")
		if host == "" {
			continue
		}

		root := host
		if net.ParseIP(host) == nil {
			if etld, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && etld != "" {
				root = etld
			}
		}

		if _, ok := seedSeen[seedURL]; !ok {
			seedSeen[seedURL] = struct{}{}
			seeds = append(seeds, seedURL)
		}
		if _, ok := domSeen[host]; !ok {
			domSeen[host] = struct{}{}
			domains = append(domains, host)
		}
		if _, ok := rootSeen[root]; !ok {
			rootSeen[root] = struct{}{}
			roots = append(roots, root)
		}
	}

	if len(seeds) == 0 {
		return nil, nil, nil, errors.New("no valid targets found in input")
	}
	slices.Sort(domains)
	slices.Sort(roots)
	return seeds, domains, roots, nil
}

func (r *Runner) resolveDBPath(roots []string) string {
	if r.options.DBPath != "" {
		return r.options.DBPath
	}
	if len(roots) == 1 && roots[0] != "" {
		return roots[0] + ".db"
	}
	return "urloot.db"
}

func (r *Runner) prepareOutputWriter() (io.Writer, func(), error) {
	if r.options.OutputFile == "" {
		return r.outWriter, func() {}, nil
	}
	if dir := strings.TrimSpace(r.options.OutputFile); dir != "" {
		f, err := os.Create(r.options.OutputFile)
		if err != nil {
			return nil, nil, fmt.Errorf("create output file %q: %w", r.options.OutputFile, err)
		}
		mw := io.MultiWriter(r.outWriter, f)
		return mw, func() { _ = f.Close() }, nil
	}
	return r.outWriter, func() {}, nil
}
