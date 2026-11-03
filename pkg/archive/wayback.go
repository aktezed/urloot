package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/aktezed/urloot/pkg/types"
)

type waybackProvider struct {
	harvester *Harvester
	baseURL   string
}

func (w *waybackProvider) Name() string {
	return "wayback"
}

func (w *waybackProvider) Fetch(ctx context.Context, domain string, includeSubs bool, out chan<- types.RawURL) error {
	targetPattern := domain + "/*"
	if includeSubs {
		targetPattern = "*." + domain + "/*"
	}

	reqURL := fmt.Sprintf(
		"%s/cdx/search/cdx?url=%s&output=json&fl=original,statuscode,mimetype&collapse=urlkey",
		w.baseURL,
		url.QueryEscape(targetPattern),
	)

	resp, err := w.harvester.doRequest(ctx, w.Name(), reqURL, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	dec := json.NewDecoder(resp.Body)
	// Read opening '[' token of JSON array
	tok, err := dec.Token()
	if err != nil {
		return nil
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return nil
	}

	rowIdx := 0
	for dec.More() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var row []string
		if err := dec.Decode(&row); err != nil {
			break
		}
		rowIdx++
		// Skip the CDX header row ["original", "statuscode", "mimetype"]
		if rowIdx == 1 && len(row) > 0 && row[0] == "original" {
			continue
		}
		if len(row) == 0 || row[0] == "" {
			continue
		}

		var statusCode int
		if len(row) > 1 && row[1] != "-" {
			statusCode, _ = strconv.Atoi(row[1])
		}
		var mimeType string
		if len(row) > 2 && row[2] != "-" {
			mimeType = row[2]
		}

		if !emitRawURL(ctx, out, types.RawURL{
			URL:         row[0],
			Method:      "GET",
			Source:      w.Name(),
			StatusCode:  statusCode,
			ContentType: mimeType,
		}) {
			return ctx.Err()
		}
	}
	return nil
}
