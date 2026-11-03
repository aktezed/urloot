package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/aktezed/urloot/pkg/types"
)

// shortcut: caps URLScan pagination at 10 pages (10,000 results per domain), expose a flag if deeper cursor walks are needed
const maxURLScanPages = 10

type urlscanProvider struct {
	harvester *Harvester
	baseURL   string
	apiKey    string
}

type urlscanResponse struct {
	Results []struct {
		Page struct {
			URL      string `json:"url"`
			Domain   string `json:"domain"`
			Status   any    `json:"status"`
			MimeType string `json:"mimeType"`
		} `json:"page"`
		Task struct {
			URL string `json:"url"`
		} `json:"task"`
		Sort []any `json:"sort"`
	} `json:"results"`
	HasMore bool `json:"has_more"`
}

func (u *urlscanProvider) Name() string {
	return "urlscan"
}

func (u *urlscanProvider) Fetch(ctx context.Context, domain string, includeSubs bool, out chan<- types.RawURL) error {
	var headers map[string]string
	if u.apiKey != "" {
		headers = map[string]string{"API-Key": u.apiKey}
	}

	searchAfter := ""
	for range maxURLScanPages {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		reqURL := fmt.Sprintf(
			"%s/api/v1/search/?q=%s&size=1000",
			u.baseURL,
			url.QueryEscape("domain:"+domain),
		)
		if searchAfter != "" {
			reqURL += "&search_after=" + url.QueryEscape(searchAfter)
		}

		resp, err := u.harvester.doRequest(ctx, u.Name(), reqURL, headers)
		if err != nil {
			return err
		}

		var payload urlscanResponse
		decErr := json.NewDecoder(resp.Body).Decode(&payload)
		_ = resp.Body.Close()
		if decErr != nil {
			return decErr
		}
		if len(payload.Results) == 0 {
			break
		}

		for _, res := range payload.Results {
			candidate := res.Page.URL
			if candidate == "" {
				candidate = res.Task.URL
			}
			if candidate == "" {
				continue
			}
			if !includeSubs && res.Page.Domain != "" && !strings.EqualFold(res.Page.Domain, domain) {
				continue
			}
			var statusCode int
			switch v := res.Page.Status.(type) {
			case float64:
				statusCode = int(v)
			case string:
				statusCode, _ = strconv.Atoi(v)
			}
			if !emitRawURL(ctx, out, types.RawURL{
				URL:         candidate,
				Method:      "GET",
				Source:      u.Name(),
				StatusCode:  statusCode,
				ContentType: res.Page.MimeType,
			}) {
				return ctx.Err()
			}
		}

		last := payload.Results[len(payload.Results)-1]
		if !payload.HasMore || len(last.Sort) == 0 {
			break
		}
		var parts []string
		for _, s := range last.Sort {
			parts = append(parts, fmt.Sprintf("%v", s))
		}
		searchAfter = strings.Join(parts, ",")
	}
	return nil
}
