package normalizer

import (
	"testing"

	"github.com/aktezed/urloot/pkg/types"
)

func TestNormalizeAndDeduplicate(t *testing.T) {
	n := New(Config{
		ScopeRoot: "example.com",
		Exclude:   []string{"logout.example.com", "/_health"},
	})

	// 1. Static asset pruning (.png, .woff2, .css, /wp-content/uploads/)
	staticURLs := []string{
		"https://example.com/assets/logo.png",
		"https://example.com/fonts/inter.woff2?v=1.2",
		"https://example.com/static/main.css",
		"https://example.com/wp-content/uploads/2026/11/photo.jpg",
	}
	for _, u := range staticURLs {
		if _, ok := n.Process(types.RawURL{URL: u, Source: "wayback"}); ok {
			t.Fatalf("expected static URL %q to be pruned", u)
		}
	}

	// 2. Out-of-scope and excluded host/path filtering
	excluded := []string{
		"https://evil.com/api/v1/users",
		"https://logout.example.com/session",
		"https://api.example.com/_health/ready",
	}
	for _, u := range excluded {
		if _, ok := n.Process(types.RawURL{URL: u, Source: "katana"}); ok {
			t.Fatalf("expected out-of-scope or excluded URL %q to be dropped", u)
		}
	}

	// 3. Pagination & dynamic path collapsing + tracking parameter stripping
	u1, ok1 := n.Process(types.RawURL{
		URL:    "https://API.Example.com:443/api/v1/users/1042//orders/?utm_source=newsletter&fbclid=abc123&page=1&sort=asc#section",
		Source: "wayback",
	})
	if !ok1 {
		t.Fatal("expected first dynamic URL to pass")
	}
	if u1.EndpointPath != "/api/v1/users/{int}/orders" {
		t.Fatalf("unexpected EndpointPath: got %q, want %q", u1.EndpointPath, "/api/v1/users/{int}/orders")
	}
	if u1.ParamSig != "page=<int>&sort=<str>" {
		t.Fatalf("unexpected ParamSig: got %q, want %q", u1.ParamSig, "page=<int>&sort=<str>")
	}
	if u1.URL != "https://api.example.com/api/v1/users/1042/orders?page=1&sort=asc" {
		t.Fatalf("unexpected clean URL: got %q", u1.URL)
	}

	// Second variation with different user ID and page=2 should collapse into the same URLHash
	u2, ok2 := n.Process(types.RawURL{
		URL:        "https://api.example.com/api/v1/users/99999/orders?gclid=xyz&page=2&sort=desc",
		Source:     "katana",
		StatusCode: 200,
	})
	if ok2 {
		t.Fatal("expected second pagination/ID variation to be deduplicated")
	}
	if u2.SourcePacked != "katana,wayback" {
		t.Fatalf("expected merged sources 'katana,wayback', got %q", u2.SourcePacked)
	}
	if u2.StatusCode != 200 {
		t.Fatalf("expected status code to update to 200, got %d", u2.StatusCode)
	}

	// 4. Dispatch parameter exception (?action=edit vs ?action=delete preserved up to 3 literals)
	_, okEdit := n.Process(types.RawURL{URL: "https://example.com/admin?action=edit&id=10", Source: "katana"})
	_, okDel := n.Process(types.RawURL{URL: "https://example.com/admin?action=delete&id=20", Source: "katana"})
	_, okEditDup := n.Process(types.RawURL{URL: "https://example.com/admin?action=edit&id=99", Source: "wayback"})
	if !okEdit || !okDel {
		t.Fatal("expected distinct dispatch verbs (action=edit, action=delete) to be preserved")
	}
	if okEditDup {
		t.Fatal("expected duplicate action=edit with different id to collapse")
	}

	// 5. SSRF / LFI parameter value classification (url_or_path) and UUID path tokenization
	uSSRF, okSSRF := n.Process(types.RawURL{
		URL:    "https://example.com/orgs/550e8400-e29b-41d4-a716-446655440000/webhook?redirect=https%3A%2F%2Finternal.example.com%2Fadmin",
		Source: "otx",
	})
	if !okSSRF {
		t.Fatal("expected webhook URL to pass")
	}
	if uSSRF.EndpointPath != "/orgs/{uuid}/webhook" {
		t.Fatalf("expected /orgs/{uuid}/webhook, got %q", uSSRF.EndpointPath)
	}
	if uSSRF.ParamTypes["redirect"] != "url_or_path" {
		t.Fatalf("expected redirect param type 'url_or_path', got %q", uSSRF.ParamTypes["redirect"])
	}
}
