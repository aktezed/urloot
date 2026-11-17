<h1 align="center">
  <br>
  <a href="https://github.com/aktezed/urloot"><img src="static/urloot-logo.svg" width="220px" alt="urloot"></a>
  <br>
  urloot
  <br>
</h1>

<h4 align="center">Passive and active URL harvester, normalizer, and SQLite endpoint differ</h4>

<p align="center">
<a href="https://github.com/aktezed/urloot/releases"><img src="https://img.shields.io/github/release/aktezed/urloot.svg"></a>
<a href="https://goreportcard.com/report/github.com/aktezed/urloot"><img src="https://goreportcard.com/badge/github.com/aktezed/urloot"></a>
<a href="https://pkg.go.dev/github.com/aktezed/urloot"><img src="https://pkg.go.dev/badge/github.com/aktezed/urloot.svg"></a>
<a href="https://github.com/aktezed/urloot/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

<p align="center">
  <a href="#what-it-does">What it does</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#cli-flags">CLI flags</a> •
  <a href="#license">License</a>
</p>

`urloot` collects historical and live URLs for web targets, collapses noisy variations into distinct endpoints, and stores each scan in a local SQLite database so you can see what changed on later runs.

It is built for web recon and bug bounty triage as the endpoint companion to [assfin](https://github.com/aktezed/assfin), replacing shell chains like `katana | gau | uro` with a single Go binary that needs no CGO or Python runtime.

## What it does

A scan accepts a single domain (`-d example.com`), a list file (`-l hosts.txt`), or targets piped on `STDIN`. By default, `urloot` keeps URLs under the target's eTLD+1 root domain; use `-scope` or `-exclude` to tighten or block specific hosts and path prefixes.

1. Passive archive harvesting (`pkg/archive`): queries Wayback Machine, Common Crawl, AlienVault OTX, and URLScan.io concurrently under per-provider rate limits. If one archive times out or returns HTTP 429 or 5xx, `urloot` logs a warning and continues with the remaining sources.
2. Active crawling (`pkg/crawler`): spiders live seed URLs for links, HTML forms and inputs, `<script src>` JavaScript files, inline scripts, `robots.txt`, and `sitemap.xml`, backing off per host when it hits HTTP 429 or 403 responses.
3. Normalization and noise filtering (`pkg/normalizer`): strips static assets (images, fonts, stylesheets, media, source maps), rejects malformed or concatenated archive strings, and drops marketing query parameters such as `utm_*`, `fbclid`, `gclid`, and `_ga`. Dynamic path segments collapse into tokens (`/api/v1/users/1042` becomes `/api/v1/users/{int}`), and query parameter values are classified as `int`, `float`, `bool`, `uuid`, `date`, `hash`, `url_or_path`, `str`, or `empty`. On dispatch parameters (`action`, `cmd`, `mode`, `type`, `view`), up to 3 distinct literal verbs are kept per route.
4. SQLite storage and diffing (`pkg/store`): saves `scans`, `endpoint_paths`, `urls`, and `params` to `<domain>.db` (or `urloot.db` for multi-root scans; pass `-no-db` to run in memory only). Re-running against the same database marks newly seen routes and parameters with `is_new`, and `query` mode lets you filter stored results offline without hitting any target again.

## Installation

```bash
go install github.com/aktezed/urloot@latest
```

Or build from source into `bin/urloot`:

```bash
git clone https://github.com/aktezed/urloot.git
cd urloot
make build
```

## Usage

### Run a full scan on a domain

```bash
urloot -d example.com
```

This queries all passive archives and spiders live pages at depth 3, saves deduplicated endpoints to `example.com.db`, and prints a terminal dossier showing totals, source provenance, per-host distribution, `url_or_path` parameter candidates, and the top 100 routes. When stdout is piped, `urloot` automatically switches from `table` to `list` (one URL per line); pass `-o json` for newline-delimited JSON.

### Cap noisy subdomains in passive mode

```bash
urloot -d example.com -no-active -max-per-host 50
```

Passive archives are often dominated by one promotional or helpdesk hostname. `-max-per-host` caps how many deduplicated endpoints are kept per host during a scan, and the end-of-run host distribution shows whether one hostname carried the results.

### Pipe alive hosts from `assfin` into `urloot` and `nuclei`

```bash
assfin -d example.com -alive -o list -s | urloot -db example-urls.db --new-only -o list -s | nuclei
```

Running with `--new-only -s` suppresses the banner and progress logs and outputs only endpoints first discovered in that scan, keeping downstream scanners focused on new surface.

### Query saved endpoints offline

```bash
urloot query -db example.com.db --new-only -o list
```

Query mode reads the SQLite file without making network requests. You can also filter by `-host`, `-path`, `-source`, `-ext`, or `-status`.

### Find high-interest parameters for SSRF, LFI, or open redirect testing

```bash
urloot query -db example.com.db -param-type url_or_path -o list
```

Combine `-has-params`, `-param`, and `-param-type` (`int`, `uuid`, `hash`, `url_or_path`, `str`) to pull specific parameter patterns out of a previous scan.

### Run custom read-only SQL

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
