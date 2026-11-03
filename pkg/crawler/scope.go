package crawler

import (
	"net"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

// ScopeGuard enforces domain, eTLD+1, and path exclusion boundaries during active crawling.
type ScopeGuard struct {
	mu           sync.Mutex
	allowedRoots map[string]struct{}
	rootCache    map[string]string
	exclude      []string
}

// NewScopeGuard creates a ScopeGuard initialized with explicit scope roots and exclusions.
func NewScopeGuard(scopeRoot string, seeds []string, exclude []string) *ScopeGuard {
	sg := &ScopeGuard{
		allowedRoots: make(map[string]struct{}),
		rootCache:    make(map[string]string, 64),
		exclude:      exclude,
	}
	if s := normalizeHost(scopeRoot); s != "" {
		sg.allowedRoots[s] = struct{}{}
		sg.allowedRoots[sg.RootDomain(s)] = struct{}{}
	}
	for _, seed := range seeds {
		h := extractSeedHost(seed)
		if h != "" {
			sg.allowedRoots[h] = struct{}{}
			sg.allowedRoots[sg.RootDomain(h)] = struct{}{}
		}
	}
	return sg
}

// RootDomain returns the eTLD+1 root domain for a hostname (or the IP itself).
func (sg *ScopeGuard) RootDomain(host string) string {
	host = normalizeHost(host)
	if host == "" {
		return ""
	}
	if net.ParseIP(host) != nil {
		return host
	}
	sg.mu.Lock()
	if cached, ok := sg.rootCache[host]; ok {
		sg.mu.Unlock()
		return cached
	}
	sg.mu.Unlock()

	root, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || root == "" {
		root = host
	}
	sg.mu.Lock()
	sg.rootCache[host] = root
	sg.mu.Unlock()
	return root
}

// Allows reports whether u is within the allowed root scope and not excluded.
func (sg *ScopeGuard) Allows(u *url.URL) bool {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := normalizeHost(u.Hostname())
	if host == "" {
		return false
	}

	lowerPath := strings.ToLower(u.Path)
	for _, ex := range sg.exclude {
		ex = strings.ToLower(strings.TrimSpace(ex))
		if ex == "" {
			continue
		}
		if strings.HasPrefix(ex, "/") {
			if strings.HasPrefix(lowerPath, ex) {
				return false
			}
			continue
		}
		if host == ex || strings.HasSuffix(host, "."+ex) {
			return false
		}
	}

	root := sg.RootDomain(host)
	sg.mu.Lock()
	defer sg.mu.Unlock()
	if len(sg.allowedRoots) == 0 {
		return true
	}
	if _, ok := sg.allowedRoots[host]; ok {
		return true
	}
	if _, ok := sg.allowedRoots[root]; ok {
		return true
	}
	for allowed := range sg.allowedRoots {
		if strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, "*.")
	h = strings.TrimSuffix(h, ".")
	if host, _, err := net.SplitHostPort(h); err == nil && host != "" {
		return host
	}
	return h
}

func extractSeedHost(seed string) string {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return ""
	}
	if !strings.Contains(seed, "://") {
		seed = "https://" + seed
	}
	u, err := url.Parse(seed)
	if err != nil {
		return ""
	}
	return normalizeHost(u.Hostname())
}
