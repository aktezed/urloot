<h1 align="center">
  <br>
  <a href="https://github.com/aktezed/urloot"><img src="static/urloot-logo.svg" width="220px" alt="urloot"></a>
  <br>
  urloot
  <br>
</h1>

<h4 align="center">Endpoint and parameter recon in one binary</h4>

<p align="center">
<a href="https://github.com/aktezed/urloot/releases"><img src="https://img.shields.io/github/release/aktezed/urloot.svg"></a>
<a href="https://goreportcard.com/report/github.com/aktezed/urloot"><img src="https://goreportcard.com/badge/github.com/aktezed/urloot"></a>
<a href="https://pkg.go.dev/github.com/aktezed/urloot"><img src="https://pkg.go.dev/badge/github.com/aktezed/urloot.svg"></a>
<a href="https://github.com/aktezed/urloot/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

<p align="center">
  <a href="#why-urloot">Why urloot</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#cli-flags">CLI flags</a> •
  <a href="#license">License</a>
</p>

`urloot` gathers endpoints and query parameters for web recon and bug bounty testing, removes duplicate noise, and saves results to SQLite so repeat scans only show new attack surface.

## Why urloot

- One static Go binary that replaces `katana | gau | uro` pipelines with no Python runtime or CGO dependencies.
- Turns thousands of raw URLs into unique routes by stripping static files, tracking parameters, and duplicate IDs or pagination.
- Flags high-value parameters (`url_or_path`, `uuid`, `int`, `hash`) so SSRF, open redirect, and IDOR targets are easy to pull out.
- Stores scan history in SQLite so `--new-only` outputs only endpoints discovered since your last run, and `query` lets you filter past scans offline.
- Companion to [assfin](https://github.com/aktezed/assfin) for moving from live hosts straight to endpoint triage.

## Installation

```bash
go install github.com/aktezed/urloot@latest
```

Or build from source:

```bash
git clone https://github.com/aktezed/urloot.git
cd urloot
make build
```

## Usage

Scan a domain (saves to `example.com.db` and prints a summary table):

```bash
urloot -d example.com
```

Cap noisy subdomains in passive mode:

```bash
urloot -d example.com -no-active -max-per-host 50
```

Pipe live hosts from `assfin` and send only newly discovered URLs to `nuclei`:

```bash
assfin -d example.com -alive -o list -s | urloot -db example-urls.db --new-only -o list -s | nuclei
```

Query a previous scan offline for new endpoints or SSRF/redirect parameters:

```bash
urloot query -db example.com.db --new-only -o list
urloot query -db example.com.db -param-type url_or_path -o list
```

Run custom read-only SQL against saved scans:

```bash
urloot query -db example.com.db -sql "SELECT host, endpoint_path, param_name, sample_value FROM params WHERE value_type = 'uuid'"
```

## CLI flags

```text
INPUT:
   -d, -domain string       target domain or subdomain to harvest (e.g. example.com)
   -l, -list string         file containing target domains, hosts, or URLs (one per line)
   -scope string            restrict crawl and harvest to root domain (default: auto eTLD+1)
   -exclude string[]        comma-separated hosts or path prefixes to exclude

PASSIVE ARCHIVES (GAU ENGINE):
   -no-passive              disable passive archive harvesting
   -providers string[]      passive providers to query (default: wayback,commoncrawl,otx,urlscan)
   -subs                    include subdomains when querying passive archives (default: true)
   -archive-timeout int     per-provider HTTP timeout in seconds (default: 20)
   -otx-key string          optional AlienVault OTX API key
   -urlscan-key string      optional URLScan.io API key

ACTIVE CRAWLER (KATANA ENGINE):
   -no-active               disable active live web spidering
   -c, -concurrency int     concurrent spidering workers (default: 10)
   -rate int                global maximum active HTTP requests per second (default: 30)
   -depth int               maximum active crawl depth (default: 3)
   -timeout int             per-request active crawl timeout in seconds (default: 10)
   -js                      parse and extract endpoints from <script src> JS bundles (default: true)
   -H, -headers string[]    custom HTTP headers (e.g. 'Cookie: sid=1')
   -proxy string            HTTP/SOCKS5 proxy URL for active crawling

NORMALIZER (URO ENGINE):
   -no-norm                 disable path/parameter collapsing
   -keep-static             retain static media, font, and stylesheet URLs
   -blacklist-ext string[]  additional file extensions to prune
   -keep-ext string[]       file extensions to exempt from pruning
   -max-per-host int        maximum deduplicated endpoints to keep per host (0 = unlimited)

STORAGE & QUERY (SQLITE):
   -db string               SQLite database path (default: <domain>.db or urloot.db)
   -no-db                   run in-memory without writing a SQLite database
   -q, -query               run in query mode against an existing SQLite database
   -new, -new-only          output only endpoints/URLs first discovered in the latest scan
   -t, -target string       filter query by root domain
   -host string             filter query by exact hostname
   -path string             filter query by normalized endpoint path substring
   -has-params              only URLs containing query parameters
   -param string[]          filter by parameter name (comma-separated OR)
   -param-type string[]     filter by parameter value class (int,uuid,hash,url_or_path,str)
   -source string[]         filter by discovery source (wayback,commoncrawl,otx,urlscan,katana)
   -ext string[]            filter by file extension (e.g. php,json,aspx)
   -status string           filter by HTTP status codes (e.g. 200,403)
   -sql string              execute raw read-only SQL query against the database

OUTPUT & GENERAL:
   -o, -output-format string  output format: list, json, table
   -out string                write output to file path in addition to STDOUT
   -s, -silent                silent mode: suppress banner and progress logs
   -version                   show urloot version
```

## License

Released under the [MIT License](LICENSE).
