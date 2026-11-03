package normalizer

import "strings"

// trackingParamExact holds lowercase tracking and marketing query parameter keys to strip.
var trackingParamExact = map[string]struct{}{
	"fbclid":      {},
	"gclid":       {},
	"dclid":       {},
	"msclkid":     {},
	"twclid":      {},
	"yclid":       {},
	"igshid":      {},
	"mc_cid":      {},
	"mc_eid":      {},
	"_ga":         {},
	"_gl":         {},
	"_gac":        {},
	"_hsenc":      {},
	"_hsmi":       {},
	"mkt_tok":     {},
	"vero_id":     {},
	"oly_enc_id":  {},
	"oly_anon_id": {},
	"rb_clickid":  {},
	"s_kwcid":     {},
	"spm":         {},
	"scm":         {},
}

// trackingParamPrefixes holds lowercase prefixes of marketing/analytics parameters to strip.
var trackingParamPrefixes = []string{
	"utm_",
	"pk_",
	"mtm_",
	"hsa_",
	"matomo_",
}

// dispatchParamSet holds parameter names where short alphabetic verbs often route to distinct handlers.
var dispatchParamSet = map[string]struct{}{
	"action":    {},
	"cmd":       {},
	"command":   {},
	"do":        {},
	"func":      {},
	"method":    {},
	"mode":      {},
	"op":        {},
	"operation": {},
	"step":      {},
	"type":      {},
	"view":      {},
}

// IsTrackingParam reports whether a query parameter key is marketing or analytics noise.
func IsTrackingParam(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if lower == "" {
		return true
	}
	if _, ok := trackingParamExact[lower]; ok {
		return true
	}
	for _, prefix := range trackingParamPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// IsDispatchParam reports whether key is an action/dispatch parameter name and val is a short alphabetic verb.
func IsDispatchParam(lowerKey, val string) bool {
	if _, ok := dispatchParamSet[lowerKey]; !ok {
		return false
	}
	if len(val) == 0 || len(val) > 20 {
		return false
	}
	for i := 0; i < len(val); i++ {
		c := val[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// ClassifyValue inspects a parameter value using byte-level checks and returns its semantic type class:
// "empty", "int", "float", "bool", "uuid", "date", "hash", "url_or_path", or "str".
func ClassifyValue(val string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return "empty"
	}
	if isAllDigits(val) {
		return "int"
	}
	if isFloat(val) {
		return "float"
	}
	if isBool(val) {
		return "bool"
	}
	if isUUID(val) {
		return "uuid"
	}
	if isISODate(val) {
		return "date"
	}
	if isURLOrPath(val) {
		return "url_or_path"
	}
	if isHexHash(val) {
		return "hash"
	}
	return "str"
}

func isAllDigits(s string) bool {
	if len(s) == 0 || len(s) > 20 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isFloat(s string) bool {
	if len(s) < 3 || len(s) > 24 {
		return false
	}
	dot := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if dot != -1 || i == 0 || i == len(s)-1 {
				return false
			}
			dot = i
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return dot != -1
}

func isBool(s string) bool {
	if len(s) > 5 {
		return false
	}
	return strings.EqualFold(s, "true") ||
		strings.EqualFold(s, "false") ||
		strings.EqualFold(s, "yes") ||
		strings.EqualFold(s, "no")
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i := range 36 {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

func isISODate(s string) bool {
	if len(s) < 10 || len(s) > 30 {
		return false
	}
	if s[4] != '-' || s[7] != '-' {
		return false
	}
	for _, idx := range []int{0, 1, 2, 3, 5, 6, 8, 9} {
		if s[idx] < '0' || s[idx] > '9' {
			return false
		}
	}
	if len(s) == 10 {
		return true
	}
	return s[10] == 'T' || s[10] == ' '
}

func isHexHash(s string) bool {
	if len(s) < 16 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isURLOrPath(s string) bool {
	if len(s) < 2 {
		return false
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "../") || strings.HasPrefix(s, `..\`) {
		return true
	}
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "http%3a") ||
		strings.HasPrefix(lower, "https%3a") ||
		strings.HasPrefix(lower, "%2f") ||
		strings.Contains(lower, "..%2f")
}
