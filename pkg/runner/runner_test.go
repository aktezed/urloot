package runner

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aktezed/urloot/pkg/archive"
	"github.com/aktezed/urloot/pkg/types"
)

func TestRunnerEndToEndScanAndQueryDiff(t *testing.T) {
	mux := http.NewServeMux()
	var includeV2Endpoint bool

	// Active web target routes
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		body := `<a href="/api/v1/items/10?page=1&utm_source=test">Item 10</a>
		<a href="/api/v1/items/20?page=2&fbclid=noise">Item 20</a>
		<a href="/static/logo.png">Logo</a>`
		if includeV2Endpoint {
			body += `<a href="/api/v2/export?redirect=https://internal.local/dump">Export</a>`
		}
		_, _ = fmt.Fprint(w, body)
	})

	// Passive archive Wayback mock on the same server
	var targetOrigin string
	mux.HandleFunc("/cdx/search/cdx", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `[
			["original","statuscode","mimetype"],
			["%s/api/v1/items/99?page=3","200","application/json"],
			["%s/legacy/admin.php?action=edit","200","text/html"]
		]`, targetOrigin, targetOrigin)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	targetOrigin = srv.URL

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(t.TempDir(), "loot.db")

	// Scan 1: Initial discovery
	opts1 := &types.Options{
		Command:      "scan",
		Targets:      []string{srv.URL},
		Scope:        u.Hostname(),
		DBPath:       dbPath,
		OutputFormat: "list",
		Silent:       true,
		Depth:        1,
		RateLimit:    100,
		Concurrency:  4,
		Timeout:      3,
		ParseJS:      true,
	}
	r1, err := NewRunner(opts1)
	if err != nil {
		t.Fatal(err)
	}
	r1.SetHarvester(archive.NewHarvester(archive.Config{
		Providers:        []string{"wayback"},
		Timeout:          3 * time.Second,
		BaseURLOverrides: map[string]string{"wayback": srv.URL},
	}))
	var out1 bytes.Buffer
	r1.SetOutput(&out1)

	if err := r1.Run(t.Context()); err != nil {
		t.Fatalf("Scan 1 failed: %v", err)
	}
	_ = r1.Close()

	list1 := out1.String()
	// /api/v1/items/10?page=1, /api/v1/items/20?page=2, and /api/v1/items/99?page=3 must collapse into 1 route!
	if strings.Contains(list1, "utm_source") || strings.Contains(list1, "fbclid") || strings.Contains(list1, "logo.png") {
		t.Fatalf("normalizer failed to strip tracking params or static assets:\n%s", list1)
	}
	if !strings.Contains(list1, "/legacy/admin.php?action=edit") {
		t.Fatalf("expected passive archive endpoint /legacy/admin.php?action=edit in output:\n%s", list1)
	}

	// Scan 2: Enable v2 endpoint and run with --new-only
	includeV2Endpoint = true
	opts2 := &types.Options{
		Command:      "scan",
		Targets:      []string{srv.URL},
		Scope:        u.Hostname(),
		DBPath:       dbPath,
		NewOnly:      true,
		OutputFormat: "list",
		Silent:       true,
		Depth:        1,
		RateLimit:    100,
		Concurrency:  4,
		Timeout:      3,
		ParseJS:      true,
	}
	r2, err := NewRunner(opts2)
	if err != nil {
		t.Fatal(err)
	}
	r2.SetHarvester(archive.NewHarvester(archive.Config{
		Providers:        []string{"wayback"},
		Timeout:          3 * time.Second,
		BaseURLOverrides: map[string]string{"wayback": srv.URL},
	}))
	var out2 bytes.Buffer
	r2.SetOutput(&out2)

	if err := r2.Run(t.Context()); err != nil {
		t.Fatalf("Scan 2 failed: %v", err)
	}
	_ = r2.Close()

	lines2 := strings.Split(strings.TrimSpace(out2.String()), "\n")
	if len(lines2) != 1 || !strings.Contains(lines2[0], "/api/v2/export") {
		t.Fatalf("expected Scan 2 --new-only to output only /api/v2/export, got:\n%s", out2.String())
	}

	// Query Mode: verify table summary and --new-only query subcommand
	qOpts := &types.Options{
		Command:      "query",
		Query:        true,
		DBPath:       dbPath,
		OutputFormat: "table",
		Silent:       true,
	}
	rq, err := NewRunner(qOpts)
	if err != nil {
		t.Fatal(err)
	}
	var outTable bytes.Buffer
	rq.SetOutput(&outTable)
	if err := rq.Run(t.Context()); err != nil {
		t.Fatalf("Query table failed: %v", err)
	}
	_ = rq.Close()

	if !strings.Contains(outTable.String(), "ENDPOINT LOOT DOSSIER") || !strings.Contains(outTable.String(), "/api/v2/export") {
		t.Fatalf("unexpected dossier table output:\n%s", outTable.String())
	}
}
