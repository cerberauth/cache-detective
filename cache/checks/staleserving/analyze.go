// Package staleserving implements §9 of cache-detective: confirming that
// RFC 5861 stale-serving extensions (stale-while-revalidate,
// stale-if-error) actually behave as declared, rather than just trusting
// their presence in Cache-Control.
package staleserving

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
)

// Declared is the RFC 5861 stale-serving window(s) a response declares via
// Cache-Control, in seconds. A nil field means the directive is absent.
type Declared struct {
	StaleWhileRevalidate *int
	StaleIfError         *int
}

// DeclaredFrom extracts the stale-serving directives already parsed by the
// cacheability check (§1), so this check doesn't re-parse Cache-Control.
func DeclaredFrom(cc cacheability.CacheControl) Declared {
	return Declared{StaleWhileRevalidate: cc.StaleWhileRevalidate, StaleIfError: cc.StaleIfError}
}

// Any reports whether either stale-serving directive is declared.
func (d Declared) Any() bool {
	return d.StaleWhileRevalidate != nil || d.StaleIfError != nil
}

// FreshnessLifetime computes a response's freshness lifetime per RFC 9111
// §4.2.1: s-maxage (shared-cache scope, which is what fronting CDNs honor)
// takes precedence over max-age, which takes precedence over Expires minus
// the response's own Date. Zero means "unknown" — no explicit freshness
// signal to time the stale window against.
func FreshnessLifetime(cc cacheability.CacheControl, expires *time.Time, date time.Time) time.Duration {
	if cc.SMaxAge != nil {
		return time.Duration(*cc.SMaxAge) * time.Second
	}
	if cc.MaxAge != nil {
		return time.Duration(*cc.MaxAge) * time.Second
	}
	if expires != nil && !date.IsZero() {
		if d := expires.Sub(date); d > 0 {
			return d
		}
	}
	return 0
}

// AgeFromHeader parses the Age response header in seconds, defaulting to
// zero (a fresh, just-fetched response) when absent or malformed.
func AgeFromHeader(h http.Header) time.Duration {
	if a := h.Get("Age"); a != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(a)); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}

// Result is the stale-serving check's per-resource outcome.
type Result struct {
	Declared             Declared
	FreshnessLifetime    time.Duration
	WindowTooLargeToTest bool

	// SWRHonored is nil when the stale-while-revalidate window wasn't
	// actively tested (directive absent, or window too large to wait for).
	SWRHonored *bool
	// SWRBackgroundRevalidated is nil when not tested (SWRHonored isn't
	// true, so there was nothing to check a background refresh against).
	SWRBackgroundRevalidated *bool

	// SIEHonored is nil when stale-if-error wasn't actively tested
	// (directive absent, --aggressive not set, or the origin didn't honor
	// the simulated-failure probe header, leaving the result inconclusive).
	SIEHonored *bool
}
