// Package cacheability implements §1 of cache-detective: determining
// whether a response is cacheable per HTTP semantics (RFC 9111) and
// CDN-agnostic Cache-Control/Expires/Vary/Pragma parsing.
package cacheability

import (
	"strconv"
	"strings"
)

// CacheControl is a parsed Cache-Control header. Unset numeric directives
// are nil so "absent" is distinguishable from "explicitly zero".
type CacheControl struct {
	NoStore              bool
	NoCache              bool
	Private              bool
	Public               bool
	MustRevalidate       bool
	ProxyRevalidate      bool
	Immutable            bool
	NoTransform          bool
	MaxAge               *int
	SMaxAge              *int
	StaleWhileRevalidate *int
	StaleIfError         *int

	// Directives holds every directive token as written, lower-cased, for
	// evidence capture and detecting directives this parser doesn't model.
	Directives []string
}

// ParseCacheControl parses a raw Cache-Control header value. Unknown or
// malformed directives are kept in Directives but otherwise ignored, per
// RFC 9111 §5.2 ("a cache MUST ignore unrecognized cache directives").
func ParseCacheControl(header string) CacheControl {
	var cc CacheControl
	if header == "" {
		return cc
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.Trim(strings.TrimSpace(value), `"`)
		cc.Directives = append(cc.Directives, part)

		switch name {
		case "no-store":
			cc.NoStore = true
		case "no-cache":
			cc.NoCache = true
		case "private":
			cc.Private = true
		case "public":
			cc.Public = true
		case "must-revalidate":
			cc.MustRevalidate = true
		case "proxy-revalidate":
			cc.ProxyRevalidate = true
		case "immutable":
			cc.Immutable = true
		case "no-transform":
			cc.NoTransform = true
		case "max-age":
			cc.MaxAge = parseIntPtr(value)
		case "s-maxage":
			cc.SMaxAge = parseIntPtr(value)
		case "stale-while-revalidate":
			cc.StaleWhileRevalidate = parseIntPtr(value)
		case "stale-if-error":
			cc.StaleIfError = parseIntPtr(value)
		}
	}
	return cc
}

// Raw renders the parsed directives back into a single evidence string.
func (cc CacheControl) Raw() string {
	return strings.Join(cc.Directives, ", ")
}

func parseIntPtr(s string) *int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &n
}

// StatusDefaultCacheable reports whether status is understood to have
// well-defined cache semantics with no explicit freshness information, per
// RFC 9111 §3 ("Storing Responses in Caches") and its heuristic-freshness
// note in §4.2.2.
func StatusDefaultCacheable(status int) bool {
	switch status {
	case 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501:
		return true
	default:
		return false
	}
}

// MethodCacheableByDefault reports whether method is cacheable without any
// method-specific opt-in — GET and HEAD per RFC 9111 §3.
func MethodCacheableByDefault(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD":
		return true
	default:
		return false
	}
}

// MethodCanBeMadeCacheable reports whether method can be cached at all,
// given explicit freshness information in the response. RFC 9111 §3 allows
// POST responses to be cached when the response carries explicit freshness
// (Expires, or Cache-Control max-age/s-maxage) and no method-specific cache
// invalidation applies. Other methods (PUT, DELETE, PATCH, ...) are not
// cached by conforming caches regardless of freshness.
func MethodCanBeMadeCacheable(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "POST":
		return true
	default:
		return false
	}
}
