package crawler

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aktezed/urloot/pkg/normalizer"
	"github.com/aktezed/urloot/pkg/types"
	"github.com/projectdiscovery/useragent"
	"golang.org/x/net/html"
	"golang.org/x/time/rate"
)

const (
	maxBodyBytes          = 2 << 20 // 2 MiB max response body read per page/script
	wafBlockCircuitLimit  = 8       // stop spidering a host after 8 consecutive 429/403 blocks
	wafThrottleStartLimit = 3       // apply adaptive delay after 3 consecutive 429/403 blocks
)

var (
	// shortcut: regex extraction avoids go-tree-sitter CGO dependency, switch to a pure-Go JS lexer if obfuscated ASTs need evaluation
	jsEndpointRe = regexp.MustCompile(`(?:"|'|` + "`" + `)((?:https?://[^"'` + "`" + `\s<>]{4,250})|(?:/[a-zA-Z0-9_.\-/${}]{1,200}(?:\?[a-zA-Z0-9_.\-&=%${}]{1,200})?))(?:"|'|` + "`" + `)`)
	// Matches template literal expressions like ${userId} so they can be replaced with a concrete integer sample.
	jsTemplateVarRe = regexp.MustCompile(`\$\{[^}]+\}`)
	// Matches <loc>...</loc> entries inside sitemap.xml.
	sitemapLocRe = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)
)

// Config holds configuration for the active web crawler.
type Config struct {
	Concurrency int
	RateLimit   int
	MaxDepth    int
	Timeout     time.Duration
	ParseJS     bool
	Headers     []string
	Proxy       string
	ScopeRoot   string
	Exclude     []string
}

type crawlTask struct {
	rawURL string
	depth  int
	isJS   bool
}

type hostWAFState struct {
	consecutiveBlocks int
}

// Crawler performs controlled, WAF-safe active web spidering (HTML, forms, JS bundles, robots.txt, sitemap.xml).
type Crawler struct {
	cfg     Config
	client  *http.Client
	limiter *rate.Limiter
	headers map[string]string

	mu        sync.Mutex
	visited   map[string]struct{}
	hostState map[string]*hostWAFState
}

// New creates a new active Crawler with the given configuration.
func New(cfg Config) (*Crawler, error) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 30
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 3
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     20 * time.Second,
	}
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	hdrs := make(map[string]string)
	for _, h := range cfg.Headers {
		if k, v, ok := strings.Cut(h, ":"); ok {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if k != "" {
				hdrs[k] = v
			}
		}
	}

	return &Crawler{
		cfg:       cfg,
		client:    client,
		limiter:   rate.NewLimiter(rate.Limit(cfg.RateLimit), max(cfg.RateLimit/2, 1)),
		headers:   hdrs,
		visited:   make(map[string]struct{}, 1024),
		hostState: make(map[string]*hostWAFState, 32),
	}, nil
}

// Crawl spiders the provided target seeds up to MaxDepth and streams discovered RawURLs to out.
func (c *Crawler) Crawl(ctx context.Context, seeds []string, out chan<- types.RawURL) {
	if len(seeds) == 0 {
		return
	}
	scope := NewScopeGuard(c.cfg.ScopeRoot, seeds, c.cfg.Exclude)

	var currentLevel []crawlTask
	seededOrigins := make(map[string]struct{})

	for _, s := range seeds {
		baseURL := normalizeSeedURL(s)
		if baseURL == "" {
			continue
		}
		u, err := url.Parse(baseURL)
		if err != nil || !scope.Allows(u) {
			continue
		}
		if c.markVisited(baseURL) {
			currentLevel = append(currentLevel, crawlTask{rawURL: baseURL, depth: 0})
		}
		origin := u.Scheme + "://" + u.Host
		if _, seenOrigin := seededOrigins[origin]; !seenOrigin {
			seededOrigins[origin] = struct{}{}
			robotsURL := origin + "/robots.txt"
			sitemapURL := origin + "/sitemap.xml"
			if c.markVisited(robotsURL) {
				currentLevel = append(currentLevel, crawlTask{rawURL: robotsURL, depth: 0})
			}
			if c.markVisited(sitemapURL) {
				currentLevel = append(currentLevel, crawlTask{rawURL: sitemapURL, depth: 0})
			}
		}
	}

	sem := make(chan struct{}, c.cfg.Concurrency)

	for depth := 0; depth <= c.cfg.MaxDepth && len(currentLevel) > 0; depth++ {
		if ctx.Err() != nil {
			return
		}
		var (
			nextMu    sync.Mutex
			nextLevel []crawlTask
			wg        sync.WaitGroup
		)

		for _, task := range currentLevel {
			if ctx.Err() != nil {
				break
			}
			select {
			case <-ctx.Done():
				break
			case sem <- struct{}{}:
			}

			wg.Add(1)
			go func(t crawlTask) {
				defer wg.Done()
				defer func() { <-sem }()

				children := c.processTask(ctx, t, scope, out)
				if len(children) > 0 && t.depth < c.cfg.MaxDepth {
					nextMu.Lock()
					nextLevel = append(nextLevel, children...)
					nextMu.Unlock()
				}
			}(task)
		}

		wg.Wait()
		currentLevel = nextLevel
	}
}

func (c *Crawler) processTask(ctx context.Context, task crawlTask, scope *ScopeGuard, out chan<- types.RawURL) []crawlTask {
	u, err := url.Parse(task.rawURL)
	if err != nil || !scope.Allows(u) {
		return nil
	}

	host := strings.ToLower(u.Hostname())
	if c.isHostCircuitBroken(host) {
		return nil
	}

	if err := c.waitRateAndBackoff(ctx, host); err != nil {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, task.rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", pickCrawlerUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,application/javascript,*/*;q=0.8")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		// If https:// seed failed on initial connection, try http:// fallback at depth 0
		if task.depth == 0 && strings.HasPrefix(task.rawURL, "https://") {
			httpFallback := "http://" + strings.TrimPrefix(task.rawURL, "https://")
			if c.markVisited(httpFallback) {
				return []crawlTask{{rawURL: httpFallback, depth: 0}}
			}
		}
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
		c.recordHostBlock(host)
	} else {
		c.resetHostBlock(host)
	}

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode >= 500 {
		return nil
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if mediaType, _, ok := strings.Cut(contentType, ";"); ok && mediaType != "" {
		contentType = strings.TrimSpace(mediaType)
	}

	// Emit the fetched page/endpoint itself (excluding boilerplate robots.txt/sitemap.xml 404s)
	emitRaw(ctx, out, types.RawURL{
		URL:         resp.Request.URL.String(),
		Method:      "GET",
		Source:      "katana",
		StatusCode:  resp.StatusCode,
		ContentType: contentType,
	})

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil || len(body) == 0 {
		return nil
	}

	baseURL := resp.Request.URL
	lowerPath := strings.ToLower(baseURL.Path)

	var discovered []crawlTask
	addCandidate := func(rawRef, method string, isJSAsset bool) {
		resolved, ok := resolveCandidateURL(baseURL, rawRef, scope)
		if !ok {
			return
		}
		emitRaw(ctx, out, types.RawURL{
			URL:    resolved,
			Method: method,
			Source: "katana",
		})
		// Queue GET candidates for deeper spidering if not static media
		if method == "GET" && (isJSAsset || !isSkippedCrawlTarget(resolved)) {
			if c.markVisited(resolved) {
				discovered = append(discovered, crawlTask{
					rawURL: resolved,
					depth:  task.depth + 1,
					isJS:   isJSAsset,
				})
			}
		}
	}

	switch {
	case strings.HasSuffix(lowerPath, "/robots.txt"):
		for _, ref := range parseRobotsTxt(body) {
			addCandidate(ref, "GET", false)
		}
	case strings.HasSuffix(lowerPath, "sitemap.xml") || strings.Contains(contentType, "xml"):
		for _, ref := range parseSitemapXML(body) {
			addCandidate(ref, "GET", false)
		}
	case task.isJS || strings.Contains(contentType, "javascript") || strings.HasSuffix(lowerPath, ".js"):
		if c.cfg.ParseJS {
			for _, ref := range extractJSEndpoints(body) {
				addCandidate(ref, "GET", false)
			}
		}
	default:
		links, forms, scripts, inlineScripts := parseHTMLDocument(body, baseURL)
		for _, link := range links {
			addCandidate(link, "GET", false)
		}
		for _, form := range forms {
			addCandidate(form.url, form.method, false)
		}
		if c.cfg.ParseJS {
			for _, scriptURL := range scripts {
				addCandidate(scriptURL, "GET", true)
			}
			for _, inline := range inlineScripts {
				for _, ref := range extractJSEndpoints([]byte(inline)) {
					addCandidate(ref, "GET", false)
				}
			}
		}
	}

	return discovered
}

type formAction struct {
	url    string
	method string
}

// parseHTMLDocument tokenizes HTML to extract links, form actions (with synthesized input parameters),
// external <script src> URLs, and inline <script> contents.
func parseHTMLDocument(body []byte, base *url.URL) (links []string, forms []formAction, scripts []string, inlineJS []string) {
	z := html.NewTokenizer(bytes.NewReader(body))

	var (
		inScript      bool
		inForm        bool
		formActionURL string
		formMethod    string
		formParams    url.Values
	)

	flushForm := func() {
		if !inForm {
			return
		}
		inForm = false
		target := formActionURL
		if target == "" && base != nil {
			target = base.Path
		}
		u, err := base.Parse(target)
		if err != nil {
			return
		}
		if len(formParams) > 0 {
			q := u.Query()
			for k, vals := range formParams {
				if !q.Has(k) && len(vals) > 0 {
					q.Set(k, vals[0])
				}
			}
			u.RawQuery = q.Encode()
		}
		forms = append(forms, formAction{
			url:    u.String(),
			method: formMethod,
		})
	}

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			flushForm()
			return links, forms, scripts, inlineJS

		case html.TextToken:
			if inScript {
				txt := strings.TrimSpace(string(z.Text()))
				if txt != "" {
					inlineJS = append(inlineJS, txt)
				}
			}

		case html.EndTagToken:
			tn, _ := z.TagName()
			switch string(tn) {
			case "script":
				inScript = false
			case "form":
				flushForm()
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			tn, hasAttr := z.TagName()
			tag := string(tn)
			if tag == "script" && tt == html.StartTagToken {
				inScript = true
			}
			if !hasAttr && tag != "form" {
				continue
			}
			attrs := readAttrs(z)

			switch tag {
			case "a", "area", "link":
				if href := attrs["href"]; href != "" {
					links = append(links, href)
				}
			case "iframe", "frame", "embed":
				if src := attrs["src"]; src != "" {
					links = append(links, src)
				}
			case "object":
				if data := attrs["data"]; data != "" {
					links = append(links, data)
				}
			case "script":
				if src := attrs["src"]; src != "" {
					inScript = false
					scripts = append(scripts, src)
				}
			case "form":
				flushForm()
				inForm = true
				formActionURL = attrs["action"]
				formMethod = strings.ToUpper(strings.TrimSpace(attrs["method"]))
				if formMethod == "" {
					formMethod = "GET"
				}
				formParams = make(url.Values)
			case "input", "select", "textarea":
				if inForm {
					if name := strings.TrimSpace(attrs["name"]); name != "" {
						val := attrs["value"]
						if val == "" {
							val = "1"
						}
						formParams.Set(name, val)
					}
				}
			}
		}
	}
}

func readAttrs(z *html.Tokenizer) map[string]string {
	m := make(map[string]string, 4)
	for {
		k, v, more := z.TagAttr()
		if len(k) > 0 {
			m[strings.ToLower(string(k))] = string(v)
		}
		if !more {
			break
		}
	}
	return m
}

func extractJSEndpoints(body []byte) []string {
	matches := jsEndpointRe.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	var out []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		cand := strings.TrimSpace(string(m[1]))
		if cand == "" || cand == "/" || strings.HasPrefix(cand, "//") {
			continue
		}
		// Replace JS template interpolations (${id}) with a sample integer so normalizer tokenizes it as {int}.
		if strings.Contains(cand, "${") {
			cand = jsTemplateVarRe.ReplaceAllString(cand, "1")
		}
		// Skip obvious MIME types or module specifiers like "text/javascript" or "application/json"
		if !strings.HasPrefix(cand, "http") && isLikelyMIMEOrNoise(cand) {
			continue
		}
		if _, dup := seen[cand]; dup {
			continue
		}
		seen[cand] = struct{}{}
		out = append(out, cand)
	}
	return out
}

func isLikelyMIMEOrNoise(pathCand string) bool {
	lower := strings.ToLower(pathCand)
	noisePrefixes := []string{
		"/application/", "/text/", "/image/", "/audio/", "/video/", "/multipart/",
		"/node_modules/", "/webpack/",
	}
	for _, p := range noisePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func parseRobotsTxt(body []byte) []string {
	var out []string
	lines := strings.SplitSeq(string(body), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "allow:"), strings.HasPrefix(lower, "disallow:"):
			idx := strings.IndexByte(line, ':')
			if idx > 0 {
				val := strings.TrimSpace(line[idx+1:])
				val = strings.ReplaceAll(val, "*", "")
				val = strings.TrimSuffix(val, "$")
				if strings.HasPrefix(val, "/") && val != "/" {
					out = append(out, val)
				}
			}
		case strings.HasPrefix(lower, "sitemap:"):
			idx := strings.IndexByte(line, ':')
			if idx > 0 {
				val := strings.TrimSpace(line[idx+1:])
				if strings.HasPrefix(strings.ToLower(val), "http") {
					out = append(out, val)
				}
			}
		}
	}
	return out
}

func parseSitemapXML(body []byte) []string {
	matches := sitemapLocRe.FindAllSubmatch(body, -1)
	var out []string
	for _, m := range matches {
		if len(m) > 1 {
			out = append(out, strings.TrimSpace(string(m[1])))
		}
	}
	return out
}

func resolveCandidateURL(base *url.URL, rawRef string, scope *ScopeGuard) (string, bool) {
	rawRef = strings.TrimSpace(rawRef)
	if rawRef == "" || strings.HasPrefix(rawRef, "#") {
		return "", false
	}
	lower := strings.ToLower(rawRef)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "data:") {
		return "", false
	}

	u, err := base.Parse(rawRef)
	if err != nil || !scope.Allows(u) {
		return "", false
	}
	u.Fragment = ""
	return u.String(), true
}

func isSkippedCrawlTarget(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	ext := normalizer.ExtractExtension(u.Path)
	switch ext {
	case "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif",
		"woff", "woff2", "ttf", "eot", "otf", "css", "mp4", "mp3", "webm", "pdf", "zip", "gz":
		return true
	}
	return false
}

func normalizeSeedURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(strings.ToLower(s), "http://") && !strings.HasPrefix(strings.ToLower(s), "https://") {
		s = "https://" + strings.TrimPrefix(s, "//")
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

func (c *Crawler) markVisited(u string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.visited[u]; exists {
		return false
	}
	c.visited[u] = struct{}{}
	return true
}

func (c *Crawler) isHostCircuitBroken(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.hostState[host]
	return ok && st.consecutiveBlocks >= wafBlockCircuitLimit
}

func (c *Crawler) recordHostBlock(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.hostState[host]
	if !ok {
		st = &hostWAFState{}
		c.hostState[host] = st
	}
	st.consecutiveBlocks++
}

func (c *Crawler) resetHostBlock(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st, ok := c.hostState[host]; ok {
		st.consecutiveBlocks = 0
	}
}

func (c *Crawler) waitRateAndBackoff(ctx context.Context, host string) error {
	if err := c.limiter.Wait(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	blocks := 0
	if st, ok := c.hostState[host]; ok {
		blocks = st.consecutiveBlocks
	}
	c.mu.Unlock()

	if blocks >= wafThrottleStartLimit {
		delay := time.Duration(blocks-wafThrottleStartLimit+1) * 150 * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil
}

func pickCrawlerUA() string {
	if filters := useragent.PickRandom(); filters.Raw != "" {
		return filters.Raw
	}
	return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
}

func emitRaw(ctx context.Context, out chan<- types.RawURL, item types.RawURL) {
	select {
	case <-ctx.Done():
	case out <- item:
	}
}
