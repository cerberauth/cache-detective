package security_test

import (
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/security"
)

// swapDiscoveredQuirks temporarily points cdn.DiscoveredQuirks at store for
// the duration of the test, restoring the original afterwards — needed
// because URLParserDiscrepancyCheck reads the package-level store directly.
func swapDiscoveredQuirks(t *testing.T, store *cdn.QuirkStore) {
	t.Helper()
	original := cdn.DiscoveredQuirks
	cdn.DiscoveredQuirks = store
	t.Cleanup(func() { cdn.DiscoveredQuirks = original })
}

// normalizingCacheServer simulates a single-slot shared cache in front of an
// origin that reflects X-Forwarded-Host site-wide (any path, including a
// nonexistent one) while the cache keys on normalize(path) — path.Clean for
// the plain "/../" form, or a backslash-aware variant of it for the
// "%5c..%5c" form (percent-decoded by net/http into a literal backslash).
// When normalizes is false the cache keys on the raw path verbatim, so a
// traversal detour can never land on the plain victim path's entry.
func normalizingCacheServer(normalizes bool) *httptest.Server {
	var mu sync.Mutex
	cached := map[string]string{}
	normalize := func(p string) string {
		if !normalizes {
			return p
		}
		return path.Clean(strings.ReplaceAll(p, `\`, "/"))
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := normalize(r.URL.Path)
		marker := r.Header.Get("X-Forwarded-Host")

		mu.Lock()
		defer mu.Unlock()
		if marker != "" {
			cached[key] = "marker=" + marker
		}
		if body, ok := cached[key]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte("plain"))
	}))
}

func TestURLParserDiscrepancy_GatedOffWithoutAggressive(t *testing.T) {
	srv := normalizingCacheServer(true)
	defer srv.Close()

	res := runChain(t, (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults(), srv.URL, "/", checkbase.CheckIDURLParserDiscrepancy, security.URLParserDiscrepancyCheck, security.DelimiterMapperCheck)
	assert.False(t, res.Skipped)
	assert.Empty(t, res.Observations)
}

func TestURLParserDiscrepancy_DetectsKeyNormalizationPoisoning(t *testing.T) {
	srv := normalizingCacheServer(true)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(30), srv.URL, "/", checkbase.CheckIDURLParserDiscrepancy, security.URLParserDiscrepancyCheck, security.DelimiterMapperCheck)
	require.NotEmpty(t, res.Observations)
	var plain, backslash bool
	for _, o := range res.Observations {
		if o.Title == "Cache-key normalization poisoning (plain traversal)" {
			plain = true
			assert.Equal(t, checkbase.SeverityCritical, o.Metadata[checkbase.SeverityKey])
		}
		if o.Title == "Cache-key normalization poisoning (encoded-backslash traversal)" {
			backslash = true
		}
	}
	assert.True(t, plain, "observations: %+v", res.Observations)
	assert.True(t, backslash, "observations: %+v", res.Observations)
}

func TestURLParserDiscrepancy_VerbatimKeyingNotFlagged(t *testing.T) {
	srv := normalizingCacheServer(false)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(30), srv.URL, "/", checkbase.CheckIDURLParserDiscrepancy, security.URLParserDiscrepancyCheck, security.DelimiterMapperCheck)
	for _, o := range res.Observations {
		assert.NotContains(t, o.Title, "Cache-key normalization poisoning")
	}
}

// delimiterOriginServer simulates an origin that treats delim as an
// origin-only path delimiter (truncates its route there, same way
// DelimiterMapperDef's own mapping probe detects it) and reflects
// X-Forwarded-Host site-wide, fronted by a cache that collapses "/../"
// dot-segments before keying (CacheTraversal == NormalizesBeforeRules) but
// never recognizes delim as a delimiter of its own (keys past it verbatim).
func delimiterOriginServer(delim string) *httptest.Server {
	var mu sync.Mutex
	cached := map[string]string{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Path
		// Origin-only truncation: everything from delim onward is ignored
		// when routing, same as DelimiterMapperCheck's own mapping probe
		// exploits (R2 == R0 for a delimiter+suffix request).
		routed := raw
		if idx := strings.Index(raw, delim); idx >= 0 {
			routed = raw[:idx]
		}
		// Cache keys on path.Clean of the raw (undelimited-aware) path —
		// collapses "/../" but has no special handling for delim itself.
		key := path.Clean(raw)
		marker := r.Header.Get("X-Forwarded-Host")

		mu.Lock()
		defer mu.Unlock()
		if marker != "" {
			cached[key] = "marker=" + marker + " routed=" + routed
		}
		if body, ok := cached[key]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte("plain:" + routed))
	}))
}

func TestURLParserDiscrepancy_DetectsBackendDelimiterPoisoning(t *testing.T) {
	store := cdn.NewQuirkStore()
	srv := delimiterOriginServer("$")
	defer srv.Close()
	origin := srv.URL
	store.Record(cdn.TargetQuirks{
		Origin:         origin,
		Delimiters:     []cdn.DelimiterDiscrepancy{{Delimiter: "$", OriginOnly: true, Cacheable: true}},
		CacheTraversal: cdn.NormalizesBeforeRules,
	})
	swapDiscoveredQuirks(t, store)

	res := runChain(t, aggressiveCtx(10), srv.URL, "/", checkbase.CheckIDURLParserDiscrepancy, security.URLParserDiscrepancyCheck, security.DelimiterMapperCheck)
	var found bool
	for _, o := range res.Observations {
		if o.Title == `Cache-key poisoning via back-end delimiter "$"` {
			found = true
			assert.Equal(t, checkbase.SeverityCritical, o.Metadata[checkbase.SeverityKey])
		}
	}
	assert.True(t, found, "observations: %+v", res.Observations)
}

// delimiterCacheServer simulates a cache that truncates its key at delim
// (cache-only direction — the same mechanism DelimiterMapperDef's own
// probeCacheOnlyDelimiter confirms) fronting an origin that collapses
// "/../" dot-segments when routing (OriginNormalizesTraversal) and
// reflects X-Forwarded-Host site-wide.
func delimiterCacheServer(delim string) *httptest.Server {
	var mu sync.Mutex
	cached := map[string]string{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Path
		// Origin routes the full raw path with "/../" collapsed.
		routed := path.Clean(raw)
		// Cache truncates its key at the first occurrence of delim.
		key := raw
		if idx := strings.Index(raw, delim); idx >= 0 {
			key = raw[:idx]
		}
		marker := r.Header.Get("X-Forwarded-Host")

		mu.Lock()
		defer mu.Unlock()
		if marker != "" {
			cached[key] = "marker=" + marker + " routed=" + routed
		}
		if body, ok := cached[key]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte("plain:" + routed))
	}))
}

func TestURLParserDiscrepancy_DetectsFrontendDelimiterPoisoning(t *testing.T) {
	store := cdn.NewQuirkStore()
	srv := delimiterCacheServer("#")
	defer srv.Close()
	origin := srv.URL
	originNormalizes := true
	store.Record(cdn.TargetQuirks{
		Origin:                    origin,
		Delimiters:                []cdn.DelimiterDiscrepancy{{Delimiter: "#", CacheOnly: true, Cacheable: true}},
		OriginNormalizesTraversal: &originNormalizes,
	})
	swapDiscoveredQuirks(t, store)

	res := runChain(t, aggressiveCtx(10), srv.URL, "/", checkbase.CheckIDURLParserDiscrepancy, security.URLParserDiscrepancyCheck, security.DelimiterMapperCheck)
	var found bool
	for _, o := range res.Observations {
		if o.Title == `Cache-key poisoning via front-end delimiter "#"` {
			found = true
			assert.Equal(t, checkbase.SeverityCritical, o.Metadata[checkbase.SeverityKey])
		}
	}
	assert.True(t, found, "observations: %+v", res.Observations)
}

func TestURLParserDiscrepancy_RespectsRequestBudget(t *testing.T) {
	var mu sync.Mutex
	var probes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ".." only ever appears in this check's own poison paths (dot-segment
		// or backslash-spelled traversal) — the rest of the §5 chain never
		// puts ".." in a request path, so counting it isolates this check's
		// own requests from UnkeyedHeaderCheck/ResponseSplittingCheck, which
		// also legitimately set X-Forwarded-Host on their own requests.
		if strings.Contains(r.URL.Path, "..") {
			mu.Lock()
			probes++
			mu.Unlock()
		}
		_, _ = w.Write([]byte("static"))
	}))
	defer srv.Close()

	runChain(t, aggressiveCtx(3), srv.URL, "/", checkbase.CheckIDURLParserDiscrepancy, security.URLParserDiscrepancyCheck, security.DelimiterMapperCheck)

	mu.Lock()
	defer mu.Unlock()
	assert.LessOrEqual(t, probes, 3)
}
