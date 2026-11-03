package archive

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"sync"

	"github.com/aktezed/urloot/pkg/types"
)

type commonCrawlProvider struct {
	harvester *Harvester
	baseURL   string

	mu     sync.Mutex
	cdxAPI string
}

type ccIndexEntry struct {
	ID     string `json:"id"`
	CDXAPI string `json:"cdx-api"`
}

type ccRecord struct {
	URL    string `json:"url"`
	Status string `json:"status"`
	Mime   string `json:"mime"`
}

func (c *commonCrawlProvider) Name() string {
	return "commoncrawl"
}

func (c *commonCrawlProvider) resolveCDXAPI(ctx context.Context) string {
	c.mu.Lock()
	if c.cdxAPI != "" {
		api := c.cdxAPI
		c.mu.Unlock()
		return api
	}
	c.mu.Unlock()

	fallback := c.baseURL + "/CC-MAIN-2025-18-index"
	infoURL := c.baseURL + "/collinfo.json"
	resp, err := c.harvester.doRequest(ctx, c.Name(), infoURL, nil)
	if err != nil {
		return fallback
	}
	defer func() { _ = resp.Body.Close() }()

	var entries []ccIndexEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil || len(entries) == 0 || entries[0].CDXAPI == "" {
		return fallback
	}

	c.mu.Lock()
	c.cdxAPI = entries[0].CDXAPI
	c.mu.Unlock()
	return entries[0].CDXAPI
}

func (c *commonCrawlProvider) Fetch(ctx context.Context, domain string, includeSubs bool, out chan<- types.RawURL) error {
	cdxEndpoint := c.resolveCDXAPI(ctx)
	targetPattern := domain + "/*"
	if includeSubs {
		targetPattern = "*." + domain + "/*"
	}

	reqURL := fmt.Sprintf(
		"%s?url=%s&output=json&fl=url,status,mime",
		cdxEndpoint,
		url.QueryEscape(targetPattern),
	)

	resp, err := c.harvester.doRequest(ctx, c.Name(), reqURL, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec ccRecord
		if err := json.Unmarshal(line, &rec); err != nil || rec.URL == "" {
			continue
		}
		statusCode, _ := strconv.Atoi(rec.Status)
		if !emitRawURL(ctx, out, types.RawURL{
			URL:         rec.URL,
			Method:      "GET",
			Source:      c.Name(),
			StatusCode:  statusCode,
			ContentType: rec.Mime,
		}) {
			return ctx.Err()
		}
	}
	return scanner.Err()
}
