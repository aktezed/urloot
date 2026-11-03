package archive

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aktezed/urloot/pkg/types"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/useragent"
	"golang.org/x/time/rate"
)

// Provider defines a passive historical URL archive source.
type Provider interface {
	Name() string
	Fetch(ctx context.Context, domain string, includeSubs bool, out chan<- types.RawURL) error
}

// Config holds configuration for the passive archive Harvester.
type Config struct {
	Providers  []string
	Timeout    time.Duration
	OTXKey     string
	URLScanKey string
	// BaseURLOverrides allows unit tests to redirect provider endpoints to httptest servers.
	BaseURLOverrides map[string]string
}

// Harvester coordinates concurrent passive URL harvesting across multiple archive providers.
type Harvester struct {
	providers []Provider
	client    *http.Client
	limiters  map[string]*rate.Limiter
}

// NewHarvester initializes a Harvester with the selected archive providers and rate limiters.
func NewHarvester(cfg Config) *Harvester {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     30 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	limiters := map[string]*rate.Limiter{
		"wayback":     rate.NewLimiter(rate.Limit(2), 2),
		"commoncrawl": rate.NewLimiter(rate.Limit(2), 2),
		"otx":         rate.NewLimiter(rate.Limit(4), 4),
		"urlscan":     rate.NewLimiter(rate.Limit(2), 2),
	}

	h := &Harvester{
		client:   client,
		limiters: limiters,
	}

	selected := cfg.Providers
	if len(selected) == 0 {
		selected = []string{"wayback", "commoncrawl", "otx", "urlscan"}
	}

	seen := make(map[string]bool, len(selected))
	for _, name := range selected {
		pName := strings.ToLower(strings.TrimSpace(name))
		if seen[pName] {
			continue
		}
		seen[pName] = true
		baseOverride := ""
		if cfg.BaseURLOverrides != nil {
			baseOverride = strings.TrimRight(strings.TrimSpace(cfg.BaseURLOverrides[pName]), "/")
		}
		switch pName {
		case "wayback":
			h.providers = append(h.providers, &waybackProvider{
				harvester: h,
				baseURL:   cmp.Or(baseOverride, "https://web.archive.org"),
			})
		case "commoncrawl":
			h.providers = append(h.providers, &commonCrawlProvider{
				harvester: h,
				baseURL:   cmp.Or(baseOverride, "https://index.commoncrawl.org"),
			})
		case "otx":
			h.providers = append(h.providers, &otxProvider{
				harvester: h,
				baseURL:   cmp.Or(baseOverride, "https://otx.alienvault.com"),
				apiKey:    cfg.OTXKey,
			})
		case "urlscan":
			h.providers = append(h.providers, &urlscanProvider{
				harvester: h,
				baseURL:   cmp.Or(baseOverride, "https://urlscan.io"),
				apiKey:    cfg.URLScanKey,
			})
		}
	}

	return h
}

// Harvest queries all enabled passive providers concurrently for domain and streams RawURLs to out.
// Individual provider errors are logged as warnings so a single archive outage does not abort the scan.
func (h *Harvester) Harvest(ctx context.Context, domain string, includeSubs bool, out chan<- types.RawURL) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || len(h.providers) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, prov := range h.providers {
		wg.Go(func() {
			if ctx.Err() != nil {
				return
			}
			if err := prov.Fetch(ctx, domain, includeSubs, out); err != nil && ctx.Err() == nil {
				gologger.Warning().Msgf("[archive:%s] %s: %v\n", prov.Name(), domain, err)
			}
		})
	}
	wg.Wait()
}

// doRequest performs a rate-limited HTTP GET request with retry on HTTP 429 and 5xx responses.
func (h *Harvester) doRequest(ctx context.Context, providerName, reqURL string, headers map[string]string) (*http.Response, error) {
	lim := h.limiters[providerName]
	const maxAttempts = 2

	var lastErr error
	for attempt := range maxAttempts {
		if lim != nil {
			if err := lim.Wait(ctx); err != nil {
				return nil, err
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", pickUserAgent())
		req.Header.Set("Accept", "application/json, text/plain, */*")
		for k, v := range headers {
			if v != "" {
				req.Header.Set(k, v)
			}
		}

		resp, err := h.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, providerName)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
			}
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			return nil, fmt.Errorf("unexpected HTTP %d from %s", resp.StatusCode, providerName)
		}

		return resp, nil
	}
	return nil, lastErr
}

func pickUserAgent() string {
	if filters := useragent.PickRandom(); filters.Raw != "" {
		return filters.Raw
	}
	return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
}

func emitRawURL(ctx context.Context, out chan<- types.RawURL, item types.RawURL) bool {
	if strings.TrimSpace(item.URL) == "" {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case out <- item:
		return true
	}
}
