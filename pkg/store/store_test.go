package store

import (
	"path/filepath"
	"testing"

	"github.com/aktezed/urloot/pkg/normalizer"
	"github.com/aktezed/urloot/pkg/types"
)

func TestStoreMultiScanDiffingAndQueries(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := New(dbPath, false)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	norm1 := normalizer.New(normalizer.Config{ScopeRoot: "example.com"})
	u1, _ := norm1.Process(types.RawURL{
		URL:        "https://api.example.com/v1/users/101?page=1&sort=asc",
		Source:     "wayback",
		StatusCode: 200,
	})
	u2, _ := norm1.Process(types.RawURL{
		URL:        "https://example.com/login.php?redirect=https://example.com/home",
		Source:     "katana",
		StatusCode: 200,
	})

	// Scan 1: both u1 and u2 are newly discovered
	scan1, err := st.BeginScan([]string{"example.com"}, "{}")
	if err != nil {
		t.Fatalf("BeginScan 1: %v", err)
	}
	newCount1, err := st.BatchUpsert(scan1, []*types.NormalizedURL{u1, u2})
	if err != nil {
		t.Fatalf("BatchUpsert 1: %v", err)
	}
	if newCount1 != 2 {
		t.Fatalf("expected 2 new URLs in scan 1, got %d", newCount1)
	}
	_ = st.FinishScan(scan1, 2, 2, newCount1)

	// Scan 2: u1 is seen again (from a new source "otx"), and u3 is brand new
	norm2 := normalizer.New(normalizer.Config{ScopeRoot: "example.com"})
	u1Repeat, _ := norm2.Process(types.RawURL{
		URL:    "https://api.example.com/v1/users/999?page=5&sort=desc",
		Source: "otx",
	})
	u3New, _ := norm2.Process(types.RawURL{
		URL:        "https://api.example.com/v2/graphql?query=me",
		Source:     "katana",
		StatusCode: 200,
	})

	scan2, err := st.BeginScan([]string{"example.com"}, "{}")
	if err != nil {
		t.Fatalf("BeginScan 2: %v", err)
	}
	newCount2, err := st.BatchUpsert(scan2, []*types.NormalizedURL{u1Repeat, u3New})
	if err != nil {
		t.Fatalf("BatchUpsert 2: %v", err)
	}
	if newCount2 != 1 {
		t.Fatalf("expected only 1 new URL in scan 2, got %d", newCount2)
	}
	_ = st.FinishScan(scan2, 2, 2, newCount2)

	// Query --new-only: must return only u3New
	newResults, err := st.QueryURLs(&types.Options{NewOnly: true})
	if err != nil {
		t.Fatalf("QueryURLs --new-only: %v", err)
	}
	if len(newResults) != 1 || newResults[0].EndpointPath != "/v2/graphql" {
		t.Fatalf("unexpected --new-only results: %+v", newResults)
	}

	// Query by parameter type url_or_path (SSRF/Open Redirect triage)
	ssrfResults, err := st.QueryURLs(&types.Options{
		ParamType: []string{"url_or_path"},
	})
	if err != nil {
		t.Fatalf("QueryURLs -param-type: %v", err)
	}
	if len(ssrfResults) != 1 || ssrfResults[0].EndpointPath != "/login.php" {
		t.Fatalf("expected /login.php for url_or_path param type, got %+v", ssrfResults)
	}

	// Verify provenance merge on u1 across Scan 1 (wayback) and Scan 2 (otx)
	u1Results, err := st.QueryURLs(&types.Options{
		Host: "api.example.com",
		Path: "/v1/users",
	})
	if err != nil || len(u1Results) != 1 {
		t.Fatalf("expected 1 /v1/users record, got %v (%v)", len(u1Results), err)
	}
	if u1Results[0].SourcePacked != "wayback,otx" {
		t.Fatalf("expected merged sources 'wayback,otx', got %q", u1Results[0].SourcePacked)
	}
}
