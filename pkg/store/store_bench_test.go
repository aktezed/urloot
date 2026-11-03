package store

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/aktezed/urloot/pkg/normalizer"
	"github.com/aktezed/urloot/pkg/types"
)

func BenchmarkBatchUpsert(b *testing.B) {
	dbPath := filepath.Join(b.TempDir(), "bench.db")
	st, err := New(dbPath, false)
	if err != nil {
		b.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	norm := normalizer.New(normalizer.Config{ScopeRoot: "example.com"})
	batch := make([]*types.NormalizedURL, 0, 500)
	for i := range 500 {
		u, ok := norm.Normalize(types.RawURL{
			URL:        fmt.Sprintf("https://api.example.com/v1/resource_%d/%d?page=1&filter=active", i, i),
			Source:     "wayback",
			StatusCode: 200,
		})
		if ok {
			batch = append(batch, u)
		}
	}

	scanID, err := st.BeginScan([]string{"example.com"}, "{}")
	if err != nil {
		b.Fatalf("BeginScan: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := st.BatchUpsert(scanID, batch); err != nil {
			b.Fatalf("BatchUpsert: %v", err)
		}
	}
}
