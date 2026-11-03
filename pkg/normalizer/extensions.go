package normalizer

import (
	"path"
	"strings"
)

// defaultBlacklistedExts holds lowercase extensions (without leading dot) pruned by default.
var defaultBlacklistedExts = map[string]struct{}{
	// Images
	"png": {}, "jpg": {}, "jpeg": {}, "gif": {}, "svg": {}, "ico": {},
	"webp": {}, "bmp": {}, "tiff": {}, "tif": {}, "avif": {}, "heic": {},
	// Fonts
	"woff": {}, "woff2": {}, "ttf": {}, "eot": {}, "otf": {},
	// Stylesheets & Media
	"css": {}, "less": {}, "scss": {}, "sass": {},
	"mp4": {}, "mp3": {}, "webm": {}, "avi": {}, "mov": {}, "wav": {},
	"ogg": {}, "oga": {}, "ogv": {}, "flv": {}, "mkv": {}, "m4a": {}, "m4v": {},
	// Documents, Archives & Binaries
	"pdf": {}, "zip": {}, "tar": {}, "gz": {}, "tgz": {}, "bz2": {}, "xz": {},
	"rar": {}, "7z": {}, "exe": {}, "dmg": {}, "iso": {}, "bin": {}, "msi": {},
	"deb": {}, "rpm": {}, "apk": {}, "ipa": {},
	// Source maps
	"map": {},
}

// staticPathFragments holds path substrings that serve static media/styling assets even without extensions.
var staticPathFragments = []string{
	"/_next/image",
	"/_next/static/media/",
	"/_next/static/css/",
	"/wp-content/uploads/",
	"/wp-content/themes/",
	"/wp-includes/css/",
	"/wp-includes/images/",
	"/wp-includes/fonts/",
}

// ExtractExtension returns the lowercase extension (without leading dot) of the final path segment.
func ExtractExtension(cleanPath string) string {
	if cleanPath == "" || cleanPath == "/" {
		return ""
	}
	base := path.Base(cleanPath)
	stem, rawExt, ok := strings.CutLast(base, ".")
	if !ok || stem == "" || rawExt == "" {
		return ""
	}
	ext := strings.ToLower(rawExt)
	// Guard against path parameters or version numbers like /v1.2
	for i := range len(ext) {
		c := ext[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return ""
		}
	}
	if isAllDigits(ext) {
		return ""
	}
	return ext
}

// IsStaticPathPrefix reports whether lowerPath matches known static media/theme path fragments.
func IsStaticPathPrefix(lowerPath string) bool {
	for _, frag := range staticPathFragments {
		if strings.Contains(lowerPath, frag) {
			return true
		}
	}
	return false
}
