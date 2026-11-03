package archive

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aktezed/urloot/pkg/types"
)

func TestHarvesterAllProvidersAndFailureIsolation(t *testing.T) {
	mux := http.NewServeMux()

	// 1. Wayback CDX mock
	mux.HandleFunc("/cdx/search/cdx", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `[
			["original","statuscode","mimetype"],
			["https://api.example.com/v1/users?page=1","200","application/json"],
			["https://example.com/login","200","text/html"]
		]`)
	})

	// 2. Common Crawl collinfo + index mock
	var srvURL string
	mux.HandleFunc("/collinfo.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `[{"id":"CC-MAIN-2026-18","cdx-api":"%s/cc-index"}]`, srvURL)
	})
	mux.HandleFunc("/cc-index", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = fmt.Fprintln(w, `{"url":"https://example.com/api/v2/items?limit=10","status":"200","mime":"application/json"}`)
	})

	// 3. OTX mock (simulating a 500 error to verify graceful failure isolation)
	mux.HandleFunc("/api/v1/indicators/domain/example.com/url_list", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	// 4. URLScan mock
	mux.HandleFunc("/api/v1/search/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{
			"results": [
				{
					"page": {"url": "https://admin.example.com/dashboard?tab=settings", "domain": "admin.example.com", "status": 200, "mimeType": "text/html"},
					"sort": [1700000000]
				}
			],
			"has_more": false
		}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	h := NewHarvester(Config{
		Providers: []string{"wayback", "commoncrawl", "otx", "urlscan"},
		Timeout:   3 * time.Second,
		BaseURLOverrides: map[string]string{
			"wayback":     srv.URL,
			"commoncrawl": srv.URL,
			"otx":         srv.URL,
			"urlscan":     srv.URL,
		},
	})

	out := make(chan types.RawURL, 16)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	go func() {
		h.Harvest(ctx, "example.com", true, out)
		close(out)
	}()

	bySource := make(map[string]int)
	var total int
	for item := range out {
		total++
		bySource[item.Source]++
	}

	if total != 4 {
		t.Fatalf("expected 4 total raw URLs despite OTX 500 failure, got %d", total)
	}
	if bySource["wayback"] != 2 || bySource["commoncrawl"] != 1 || bySource["urlscan"] != 1 {
		t.Fatalf("unexpected source counts: %+v", bySource)
	}
}
