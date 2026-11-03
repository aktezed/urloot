package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/aktezed/urloot/pkg/types"
)

// shortcut: caps OTX pagination at 20 pages (10,000 URLs per domain), expose a flag if deeper historical walks are needed
const maxOTXPages = 20

type otxProvider struct {
	harvester *Harvester
	baseURL   string
	apiKey    string
}

type otxResponse struct {
	URLList []struct {
		URL      string `json:"url"`
		Httpcode int    `json:"httpcode"`
	} `json:"url_list"`
	HasNext bool `json:"has_next"`
}

func (o *otxProvider) Name() string {
	return "otx"
}

func (o *otxProvider) Fetch(ctx context.Context, domain string, includeSubs bool, out chan<- types.RawURL) error {
	indicatorType := "hostname"
	if includeSubs {
		indicatorType = "domain"
	}

	var headers map[string]string
	if o.apiKey != "" {
		headers = map[string]string{"X-OTX-API-KEY": o.apiKey}
	}

	for page := 1; page <= maxOTXPages; page++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		reqURL := fmt.Sprintf(
			"%s/api/v1/indicators/%s/%s/url_list?limit=500&page=%d",
			o.baseURL,
			indicatorType,
			url.PathEscape(domain),
			page,
		)

		resp, err := o.harvester.doRequest(ctx, o.Name(), reqURL, headers)
		if err != nil {
			return err
		}

		var payload otxResponse
		decErr := json.NewDecoder(resp.Body).Decode(&payload)
		_ = resp.Body.Close()
		if decErr != nil {
			return decErr
		}

		for _, entry := range payload.URLList {
			if !emitRawURL(ctx, out, types.RawURL{
				URL:        entry.URL,
				Method:     "GET",
				Source:     o.Name(),
				StatusCode: entry.Httpcode,
			}) {
				return ctx.Err()
			}
		}

		if !payload.HasNext || len(payload.URLList) == 0 {
			break
		}
	}
	return nil
}
