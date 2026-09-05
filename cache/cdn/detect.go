package cdn

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Detection is the outcome of inspecting one response's headers for
// CDN identity and live cache state.
type Detection struct {
	CDN               string // empty when no signature matched
	State             State
	Source            string // which header the verdict came from, for evidence
	RawValue          string
	Age               *int     // seconds, from the Age header, when present
	MultiTierEvidence []string // additional headers observed that suggest a second cache tier
}

// serverTimingCacheRe matches the increasingly common convention of
// reporting cache status via Server-Timing, e.g.
// `Server-Timing: cdn-cache; desc=HIT`.
var serverTimingCacheRe = regexp.MustCompile(`(?i)cdn-cache\s*;\s*desc=([a-z_-]+)`)

// Detect inspects header for known CDN cache-status conventions (via the
// Registry) and, failing that, generic header heuristics. It never issues
// requests itself — see the livestate check for the multi-request
// HIT/MISS-pattern and timing-based fallback this feeds into.
func Detect(header http.Header) Detection {
	server := header.Get("Server")
	via := header.Get("Via")

	det := Detection{State: StateUnknown}
	if a := header.Get("Age"); a != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(a)); err == nil {
			det.Age = &n
		}
	}

	// Prefer fingerprinting the CDN first (Server/Via), then read its own
	// cache-status header — avoids ambiguity between CDNs that reuse the
	// same header name (e.g. "X-Cache") with different value vocabularies.
	if sig, ok := MatchServer(server, via); ok {
		det.CDN = sig.Name
		if raw := header.Get(sig.CacheStatusHeader); raw != "" {
			state, _ := sig.Normalize(raw)
			det.State = state
			det.Source = sig.CacheStatusHeader
			det.RawValue = raw
		}
		det.MultiTierEvidence = presentHeaders(header, sig.MultiTierHeaders)
		if det.State != StateUnknown {
			return det
		}
	}

	// Not fingerprinted by Server/Via (e.g. behind a generic reverse proxy,
	// or the CDN strips its own Server header) — try every registry entry's
	// cache-status header as a best-effort fallback.
	for _, sig := range Registry {
		raw := header.Get(sig.CacheStatusHeader)
		if raw == "" {
			continue
		}
		if state, ok := sig.Normalize(raw); ok {
			det.CDN = sig.Name
			det.State = state
			det.Source = sig.CacheStatusHeader
			det.RawValue = raw
			return det
		}
	}

	// Generic Server-Timing cdn-cache convention.
	if m := serverTimingCacheRe.FindStringSubmatch(header.Get("Server-Timing")); len(m) == 2 {
		det.Source = "Server-Timing"
		det.RawValue = m[1]
		det.State = genericState(m[1])
		return det
	}

	// Fully generic X-Cache: HIT/MISS, seen on proxies not in the registry.
	if raw := header.Get(genericXCacheHeader); raw != "" {
		det.Source = genericXCacheHeader
		det.RawValue = raw
		det.State = genericState(raw)
		return det
	}

	return det
}

func genericState(raw string) State {
	raw = strings.ToLower(raw)
	switch {
	case strings.Contains(raw, "hit"):
		return StateHit
	case strings.Contains(raw, "stale"):
		return StateStale
	case strings.Contains(raw, "expired"):
		return StateExpired
	case strings.Contains(raw, "bypass") || strings.Contains(raw, "pass"):
		return StateBypass
	case strings.Contains(raw, "miss"):
		return StateMiss
	default:
		return StateUnknown
	}
}

func presentHeaders(header http.Header, names []string) []string {
	var out []string
	for _, n := range names {
		if v := header.Get(n); v != "" {
			out = append(out, n+": "+v)
		}
	}
	return out
}
