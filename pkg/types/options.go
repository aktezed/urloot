package types

import "github.com/projectdiscovery/goflags"

// Options contains all CLI and SDK configuration parameters for urloot.
type Options struct {
	// Command mode ("scan" or "query")
	Command string `json:"command,omitempty"`

	// Input
	Domain  string              `json:"domain,omitempty"`
	List    string              `json:"list,omitempty"`
	Scope   string              `json:"scope,omitempty"`
	Exclude goflags.StringSlice `json:"exclude,omitempty"`
	Targets []string            `json:"targets,omitempty"`

	// Passive Archives (GAU Engine)
	NoPassive      bool                `json:"no_passive,omitempty"`
	Providers      goflags.StringSlice `json:"providers,omitempty"`
	IncludeSubs    bool                `json:"include_subs,omitempty"`
	ArchiveTimeout int                 `json:"archive_timeout,omitempty"`
	OTXKey         string              `json:"otx_key,omitempty"`
	URLScanKey     string              `json:"urlscan_key,omitempty"`

	// Active Crawler (Katana-style Engine)
	NoActive    bool                `json:"no_active,omitempty"`
	Concurrency int                 `json:"concurrency,omitempty"`
	RateLimit   int                 `json:"rate_limit,omitempty"`
	Depth       int                 `json:"depth,omitempty"`
	Timeout     int                 `json:"timeout,omitempty"`
	ParseJS     bool                `json:"parse_js,omitempty"`
	Headers     goflags.StringSlice `json:"headers,omitempty"`
	Proxy       string              `json:"proxy,omitempty"`

	// Normalizer (URO Engine)
	NoNormalize  bool                `json:"no_normalize,omitempty"`
	KeepStatic   bool                `json:"keep_static,omitempty"`
	BlacklistExt goflags.StringSlice `json:"blacklist_ext,omitempty"`
	KeepExt      goflags.StringSlice `json:"keep_ext,omitempty"`

	// Storage & Query (SQLite)
	DBPath    string              `json:"db_path,omitempty"`
	NoDB      bool                `json:"no_db,omitempty"`
	Query     bool                `json:"query,omitempty"`
	NewOnly   bool                `json:"new_only,omitempty"`
	Target    string              `json:"target,omitempty"`
	Host      string              `json:"host,omitempty"`
	Path      string              `json:"path,omitempty"`
	HasParams bool                `json:"has_params,omitempty"`
	Params    goflags.StringSlice `json:"params,omitempty"`
	ParamType goflags.StringSlice `json:"param_type,omitempty"`
	Sources   goflags.StringSlice `json:"sources,omitempty"`
	Ext       goflags.StringSlice `json:"ext,omitempty"`
	Status    string              `json:"status,omitempty"`
	RawSQL    string              `json:"raw_sql,omitempty"`

	// Output & General
	OutputFormat string `json:"output_format,omitempty"`
	OutputFile   string `json:"output_file,omitempty"`
	Silent       bool   `json:"silent,omitempty"`
	Version      bool   `json:"version,omitempty"`
}
