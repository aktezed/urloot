package normalizer

import (
	"net"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aktezed/urloot/pkg/types"
	"golang.org/x/net/publicsuffix"
)

const maxDispatchLiteralsPerRoute = 3

// Config configures the Normalizer and Deduplicator behavior.
type Config struct {
	NoNormalize  bool
	KeepStatic   bool
	BlacklistExt []string
	KeepExt      []string
	ScopeRoot    string
	Exclude      []string
}

// Normalizer performs stateless and stateful URL normalization and deduplication.
type Normalizer struct {
	cfg          Config
	blacklistExt map[string]struct{}

	mu           sync.Mutex
	rootCache    map[string]string
	seenURLs     map[string]*types.NormalizedURL
	dispatchSeen map[string]map[string]struct{}
}

// New creates a new Normalizer and in-memory Deduplicator with the given configuration.
func New(cfg Config) *Normalizer {
	bl := make(map[string]struct{}, len(defaultBlacklistedExts)+len(cfg.BlacklistExt))
	for k := range defaultBlacklistedExts {
		bl[k] = struct{}{}
	}
	for _, ext := range cfg.BlacklistExt {
		clean := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(ext)), ".")
		if clean != "" {
			bl[clean] = struct{}{}
		}
	}
	for _, ext := range cfg.KeepExt {
		clean := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(ext)), ".")
		delete(bl, clean)
	}
	cfg.ScopeRoot = strings.ToLower(strings.TrimSpace(cfg.ScopeRoot))

	return &Normalizer{
		cfg:          cfg,
		blacklistExt: bl,
		rootCache:    make(map[string]string, 64),
		seenURLs:     make(map[string]*types.NormalizedURL, 1024),
		dispatchSeen: make(map[string]map[string]struct{}, 128),
	}
}

// Normalize transforms a RawURL into a canonical NormalizedURL and reports whether it passed filters.
// It does not deduplicate across previous calls; use Process() for stateful deduplication.
func (n *Normalizer) Normalize(raw types.RawURL) (*types.NormalizedURL, bool) {
	rawStr := strings.TrimSpace(raw.URL)
	if rawStr == "" {
		return nil, false
	}

	// Ignore non-HTTP schemes early
	lowerRaw := strings.ToLower(rawStr)
	if strings.HasPrefix(lowerRaw, "javascript:") ||
		strings.HasPrefix(lowerRaw, "data:") ||
		strings.HasPrefix(lowerRaw, "mailto:") ||
		strings.HasPrefix(lowerRaw, "tel:") {
		return nil, false
	}
	if !strings.HasPrefix(lowerRaw, "http://") && !strings.HasPrefix(lowerRaw, "https://") {
		rawStr = "https://" + strings.TrimPrefix(rawStr, "//")
	}

	u, err := url.Parse(rawStr)
	if err != nil || u.Host == "" {
		return nil, false
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, false
	}

	// Normalize host and strip default ports
	host := strings.ToLower(u.Hostname())
	host = strings.TrimPrefix(host, "*.")
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil, false
	}
	port := u.Port()
	hostPort := host
	if port != "" && !((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) {
		hostPort = net.JoinHostPort(host, port)
	}

	root := n.resolveRoot(host)
	if !n.inScope(host, root, u.Path) {
		return nil, false
	}

	// Clean path
	cleanPath := u.Path
	if cleanPath == "" {
		cleanPath = "/"
	} else {
		for strings.Contains(cleanPath, "//") {
			cleanPath = strings.ReplaceAll(cleanPath, "//", "/")
		}
		trailingSlash := len(cleanPath) > 1 && strings.HasSuffix(cleanPath, "/")
		cleanPath = path.Clean(cleanPath)
		if !strings.HasPrefix(cleanPath, "/") {
			cleanPath = "/" + cleanPath
		}
		if trailingSlash && cleanPath != "/" {
			cleanPath = strings.TrimSuffix(cleanPath, "/")
		}
	}

	ext := ExtractExtension(cleanPath)
	if !n.cfg.KeepStatic {
		if ext != "" {
			if _, blocked := n.blacklistExt[ext]; blocked {
				return nil, false
			}
		}
		if IsStaticPathPrefix(strings.ToLower(cleanPath)) {
			return nil, false
		}
	}

	method := strings.ToUpper(strings.TrimSpace(raw.Method))
	if method == "" {
		method = "GET"
	}

	endpointPath := cleanPath
	if !n.cfg.NoNormalize {
		endpointPath = TokenizePath(cleanPath)
	}

	routeHash := hashHex64(method + "|" + scheme + "|" + hostPort + "|" + endpointPath)

	// Parse and normalize query parameters
	var (
		paramNames   []string
		paramTypes   map[string]string
		paramSamples map[string]string
		cleanQuery   url.Values
	)

	if u.RawQuery != "" {
		q, err := url.ParseQuery(u.RawQuery)
		if err == nil && len(q) > 0 {
			cleanQuery = make(url.Values, len(q))
			paramTypes = make(map[string]string, len(q))
			paramSamples = make(map[string]string, len(q))

			for k, vals := range q {
				if IsTrackingParam(k) {
					continue
				}
				normKey := strings.TrimSpace(k)
				if normKey == "" {
					continue
				}
				lowerKey := strings.ToLower(normKey)
				firstVal := ""
				if len(vals) > 0 {
					firstVal = vals[0]
				}
				cleanQuery.Set(normKey, firstVal)

				if _, exists := paramTypes[lowerKey]; !exists {
					paramNames = append(paramNames, lowerKey)
					valType := ClassifyValue(firstVal)
					paramTypes[lowerKey] = valType
					paramSamples[lowerKey] = firstVal
				}
			}
			slices.Sort(paramNames)
		}
	}

	// Build canonical parameter signature
	var paramSig string
	if len(paramNames) > 0 {
		var sb strings.Builder
		for i, k := range paramNames {
			if i > 0 {
				sb.WriteByte('&')
			}
			sb.WriteString(k)
			sb.WriteByte('=')
			if n.cfg.NoNormalize {
				sb.WriteString(paramSamples[k])
			} else {
				sigToken := n.resolveParamToken(routeHash, k, paramSamples[k], paramTypes[k])
				sb.WriteString(sigToken)
			}
		}
		paramSig = sb.String()
	}

	urlHash := hashHex64(routeHash + "|" + paramSig)

	// Reconstruct clean concrete URL (without fragments or tracking noise)
	cleanURL := url.URL{
		Scheme: scheme,
		Host:   hostPort,
		Path:   cleanPath,
	}
	if len(cleanQuery) > 0 {
		cleanURL.RawQuery = cleanQuery.Encode()
	}

	var paramsPacked string
	if len(paramNames) > 0 {
		paramsPacked = "," + strings.Join(paramNames, ",") + ","
	}

	src := strings.ToLower(strings.TrimSpace(raw.Source))
	if src == "" {
		src = "unknown"
	}
	now := time.Now().UTC().Format(time.RFC3339)

	return &types.NormalizedURL{
		URLHash:      urlHash,
		RouteHash:    routeHash,
		URL:          cleanURL.String(),
		Scheme:       scheme,
		Host:         hostPort,
		Root:         root,
		Method:       method,
		EndpointPath: endpointPath,
		SamplePath:   cleanPath,
		Ext:          ext,
		Params:       paramNames,
		ParamsPacked: paramsPacked,
		ParamTypes:   paramTypes,
		ParamSamples: paramSamples,
		ParamSig:     paramSig,
		Sources:      []string{src},
		SourcePacked: src,
		StatusCode:   raw.StatusCode,
		ContentType:  raw.ContentType,
		FirstSeen:    now,
		LastSeen:     now,
		IsNew:        true,
	}, true
}

// Process normalizes a RawURL and deduplicates it against all URLs seen in this session.
// It returns (norm, true) only on the first sighting of a canonical URLHash; subsequent
// sightings merge their provenance source and metadata into the existing record and return (existing, false).
func (n *Normalizer) Process(raw types.RawURL) (*types.NormalizedURL, bool) {
	norm, ok := n.Normalize(raw)
	if !ok {
		return nil, false
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if existing, dup := n.seenURLs[norm.URLHash]; dup {
		existing.LastSeen = norm.LastSeen
		if existing.StatusCode == 0 && norm.StatusCode != 0 {
			existing.StatusCode = norm.StatusCode
		}
		if existing.ContentType == "" && norm.ContentType != "" {
			existing.ContentType = norm.ContentType
		}
		for _, src := range norm.Sources {
			if !slices.Contains(existing.Sources, src) {
				existing.Sources = append(existing.Sources, src)
				slices.Sort(existing.Sources)
				existing.SourcePacked = strings.Join(existing.Sources, ",")
			}
		}
		return existing, false
	}

	n.seenURLs[norm.URLHash] = norm
	return norm, true
}

// Records returns a snapshot of all deduplicated NormalizedURL entries collected so far.
func (n *Normalizer) Records() []*types.NormalizedURL {
	n.mu.Lock()
	defer n.mu.Unlock()

	out := make([]*types.NormalizedURL, 0, len(n.seenURLs))
	for _, r := range n.seenURLs {
		out = append(out, r)
	}
	return out
}

func (n *Normalizer) resolveParamToken(routeHash, lowerKey, val, valType string) string {
	if !IsDispatchParam(lowerKey, val) {
		return "<" + valType + ">"
	}
	lowerVal := strings.ToLower(val)
	n.mu.Lock()
	defer n.mu.Unlock()

	bucketKey := routeHash + "|" + lowerKey
	seenSet, ok := n.dispatchSeen[bucketKey]
	if !ok {
		seenSet = make(map[string]struct{}, maxDispatchLiteralsPerRoute)
		n.dispatchSeen[bucketKey] = seenSet
	}
	if _, exists := seenSet[lowerVal]; exists {
		return lowerVal
	}
	if len(seenSet) < maxDispatchLiteralsPerRoute {
		seenSet[lowerVal] = struct{}{}
		return lowerVal
	}
	return "<str>"
}

func (n *Normalizer) resolveRoot(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	n.mu.Lock()
	if cached, ok := n.rootCache[host]; ok {
		n.mu.Unlock()
		return cached
	}
	n.mu.Unlock()

	root, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || root == "" {
		root = host
	}

	n.mu.Lock()
	n.rootCache[host] = root
	n.mu.Unlock()
	return root
}

func (n *Normalizer) inScope(host, root, urlPath string) bool {
	if n.cfg.ScopeRoot != "" {
		scope := n.cfg.ScopeRoot
		if host != scope && root != scope && !strings.HasSuffix(host, "."+scope) {
			return false
		}
	}
	lowerPath := strings.ToLower(urlPath)
	for _, ex := range n.cfg.Exclude {
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
	return true
}

// hashHex64 computes a 64-bit FNV-1a hex digest without fmt reflection overhead.
func hashHex64(s string) string {
	const (
		offset64  = 14695981039346656037
		prime64   = 1099511628211
		hexDigits = "0123456789abcdef"
	)
	var h uint64 = offset64
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	var buf [16]byte
	for i := 15; i >= 0; i-- {
		buf[i] = hexDigits[h&0x0f]
		h >>= 4
	}
	return string(buf[:])
}
