package normalizer

import (
	"testing"

	"github.com/aktezed/urloot/pkg/types"
)

func BenchmarkNormalize(b *testing.B) {
	n := New(Config{ScopeRoot: "example.com"})
	raw := types.RawURL{
		URL:        "https://api.example.com:443/api/v1/users/550e8400-e29b-41d4-a716-446655440000/orders/1042?utm_source=x&page=2&redirect=https://example.com/cb",
		Source:     "wayback",
		StatusCode: 200,
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = n.Normalize(raw)
	}
}
