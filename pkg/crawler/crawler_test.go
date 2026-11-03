package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aktezed/urloot/pkg/types"
)

func TestCrawlerHTMLFormsJSAndRobots(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<!doctype html>
<html>
<head><script src="/static/app.js"></script></head>
<body>
  <a href="/products?category=books">Books</a>
  <a href="https://external-evil.com/leak">Out of Scope</a>
  <form action="/api/v1/search" method="GET">
    <input name="q" value="golang">
    <input name="limit" value="25">
  </form>
  <script>
    fetch("/api/v1/internal/feature-flags?env=prod");
  </script>
</body>
</html>`)
	})

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintln(w, "User-agent: *\nDisallow: /admin/debug-console")
	})

	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprintf(w, `<urlset><url><loc>http://%s/docs/api-reference</loc></url></urlset>`, r.Host)
	})

	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = fmt.Fprint(w, `
			const base = "/api/v2/users/${userId}/tokens?active=true";
			axios.post("/api/v2/auth/refresh");
		`)
	})

	mux.HandleFunc("/products", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := New(Config{
		Concurrency: 4,
		RateLimit:   100,
		MaxDepth:    2,
		Timeout:     3 * time.Second,
		ParseJS:     true,
	})
	if err != nil {
		t.Fatalf("New crawler error: %v", err)
	}

	out := make(chan types.RawURL, 64)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	go func() {
		c.Crawl(ctx, []string{srv.URL}, out)
		close(out)
	}()

	var found []string
	for item := range out {
		if strings.Contains(item.URL, "external-evil.com") {
			t.Fatalf("scope guard failed: leaked external URL %q", item.URL)
		}
		found = append(found, item.URL)
	}

	joined := strings.Join(found, "\n")
	expectedSubstrings := []string{
		"/products?category=books",
		"/api/v1/search?limit=25&q=golang",
		"/api/v1/internal/feature-flags?env=prod",
		"/admin/debug-console",
		"/docs/api-reference",
		"/api/v2/users/1/tokens?active=true",
		"/api/v2/auth/refresh",
	}
	for _, exp := range expectedSubstrings {
		if !strings.Contains(joined, exp) {
			t.Errorf("expected crawler output to contain %q, got:\n%s", exp, joined)
		}
	}
}
