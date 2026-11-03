package normalizer

import "strings"

// TokenizePath normalizes dynamic segments in a cleaned URL path (such as numeric IDs, UUIDs,
// hex hashes, ISO dates, and high-entropy slugs) while preserving API version markers (v1, v2)
// and static route names.
func TokenizePath(cleanPath string) string {
	if cleanPath == "" || cleanPath == "/" {
		return "/"
	}
	trimmed := strings.TrimPrefix(cleanPath, "/")
	segments := strings.Split(trimmed, "/")
	changed := false

	for i, seg := range segments {
		if seg == "" {
			continue
		}
		tok := classifyPathSegment(seg)
		if tok != seg {
			segments[i] = tok
			changed = true
		}
	}
	if !changed {
		return cleanPath
	}
	return "/" + strings.Join(segments, "/")
}

func classifyPathSegment(seg string) string {
	// If the final segment has a file extension (e.g. "12345.json" or "report.php"),
	// inspect the stem while preserving the extension.
	ext := ""
	stem := seg
	if pre, candExt, ok := strings.CutLast(seg, "."); ok && pre != "" && candExt != "" {
		if !isAllDigits(candExt) && len(candExt) <= 8 {
			stem = pre
			ext = "." + strings.ToLower(candExt)
		}
	}

	if isVersionSegment(stem) {
		return seg
	}
	if isAllDigits(stem) {
		return "{int}" + ext
	}
	if isUUID(stem) {
		return "{uuid}" + ext
	}
	if isISODate(stem) {
		return "{date}" + ext
	}
	if isHexHash(stem) {
		return "{hash}" + ext
	}
	if isDynamicSlug(stem) {
		return "{slug}" + ext
	}
	return seg
}

func isVersionSegment(s string) bool {
	if len(s) < 2 || len(s) > 6 {
		return false
	}
	if s[0] != 'v' && s[0] != 'V' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// isDynamicSlug detects uro-style dynamic tokens in path segments:
// 1. High-entropy tokens of length >= 16 mixing digits and letters.
// 2. Identifiers containing >= 3 digits mixed with letters (e.g. "usr_94821a", "order-20261103-99").
func isDynamicSlug(s string) bool {
	if len(s) < 5 {
		return false
	}
	digits := 0
	lower := 0
	upper := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z':
			lower++
		case c >= 'A' && c <= 'Z':
			upper++
		}
	}
	if digits >= 3 && (lower+upper) > 0 {
		return true
	}
	if len(s) >= 16 && digits >= 1 && lower >= 1 && upper >= 1 {
		return true
	}
	return false
}
