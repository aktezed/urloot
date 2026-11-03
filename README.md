<h1 align="center">
  <br>
  <a href="https://github.com/aktezed/urloot"><img src="static/urloot-logo.svg" width="220px" alt="urloot"></a>
  <br>
  urloot
  <br>
</h1>

<h4 align="center">Passive & active URL harvester, heuristic normalizer, and SQLite endpoint differ</h4>

<p align="center">
<a href="https://github.com/aktezed/urloot/releases"><img src="https://img.shields.io/github/release/aktezed/urloot.svg"></a>
<a href="https://goreportcard.com/report/github.com/aktezed/urloot"><img src="https://goreportcard.com/badge/github.com/aktezed/urloot"></a>
<a href="https://pkg.go.dev/github.com/aktezed/urloot"><img src="https://pkg.go.dev/badge/github.com/aktezed/urloot.svg"></a>
<a href="https://github.com/aktezed/urloot/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage-examples">Usage</a> •
  <a href="#cli-flags">CLI Flags</a> •
  <a href="#license">License</a>
</p>

---

**urloot** (URL + Loot) is a standalone Go CLI tool and SDK for passive archive harvesting, active web crawling, heuristic URL normalization, and persistent SQLite endpoint diffing.

Built as the endpoint-level companion to [assfin](https://github.com/aktezed/assfin), `urloot` replaces fragile shell pipelines (`katana | gau | uro`) and Python runtime dependencies with a single CGO-free binary that tracks newly surfaced routes and query parameters across time.

---

## Features

1. **Multi-Mode Target Ingestion**:
   - Single domain (`-d example.com`), target list file (`-l hosts.txt`), or standard UNIX `STDIN` piping (`cat hosts.txt | urloot`).
2. **Passive Archive Harvester (`pkg/archive`)**:
   - Queries Wayback Machine, Common Crawl, AlienVault OTX, and URLScan.io concurrently.
   - Enforces per-provider token-bucket rate limits and isolates individual provider timeouts or HTTP 429/5xx errors without aborting the scan.
3. **Active Spidering Engine (`pkg/crawler`)**:
   - Crawls live web targets with configurable concurrency (`-c 10`), global rate limit (`-rate 30`), timeout (`-timeout 10`), and depth (`-depth 3`).
   - Extracts endpoints from HTML links, `<form>` actions and input fields, `<script src>` JavaScript bundles, inline scripts, `robots.txt`, and `sitemap.xml`.
   - Enforces eTLD+1 scope boundaries and applies adaptive per-host backoff when encountering HTTP 429 or 403 WAF responses.
4. **Native Go Normalizer and Deduplicator (`pkg/normalizer`)**:
   - Prunes static assets (`.png`, `.jpg`, `.svg`, `.woff2`, `.css`, `.mp4`, `.pdf`, `.zip`, `.map`) and static theme/upload prefixes.
   - Strips marketing and analytics tracking parameters (`utm_*`, `fbclid`, `gclid`, `msclkid`, `_ga`, `_gl`, `mc_cid`).
   - Tokenizes dynamic REST path segments (`/api/v1/users/1042` becomes `/api/v1/users/{int}`) and query parameter value classes (`?page=1` and `?page=2` collapse into `page=<int>`), while preserving up to 3 distinct literal verbs on dispatch parameters (`action`, `cmd`, `mode`, `type`, `view`).
5. **SQLite Endpoint Diffing (`pkg/store`)**:
   - Pure-Go embedded SQLite (`modernc.org/sqlite`) in WAL mode storing `scans`, `endpoint_paths`, `urls`, and `params`.
   - Tracks `first_seen`, `last_seen`, and `is_new` deltas across scans so operators can query only newly discovered attack surface (`urloot query -db target.db --new-only`).

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

## Usage Examples

### 1. Harvest and Spider a Single Domain

```bash
urloot -d example.com
```

### 2. Pipe Alive Hosts from `assfin` into `urloot` and `nuclei`

```bash
assfin -d example.com -alive -o list -s | urloot -db example-urls.db --new-only -o list -s | nuclei
```

### 3. Query Newly Discovered Endpoints from SQLite

```bash
urloot query -db example.com.db --new-only -o list
```

### 4. Filter Endpoints by Parameter Value Class (SSRF / Open Redirect Triage)

```bash
urloot query -db example.com.db -param-type url_or_path -o list
```

### 5. Run Custom Read-Only SQL Queries

```bash
urloot query -db example.com.db -sql "SELECT host, endpoint_path, param_name, sample_value FROM params WHERE value_type = 'uuid'"
```

## CLI Flags

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

MIT
