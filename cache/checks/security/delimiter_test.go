package security_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/security"
)

// newDelimiterEngine registers the full §5 chain the delimiter mapper depends
// on (transitively, via CPDoSCheck) plus the mapper itself.
func newDelimiterEngine(t *testing.T) *harnessx.Engine {
	t.Helper()
	return newEngine(t,
		security.UnkeyedHeaderCheck,
		security.CacheDeceptionCheck,
		security.ErrorCachingCheck,
		security.ResponseSplittingCheck,
		security.CPDoSCheck,
		security.DelimiterMapperCheck,
	)
}

func observationTitles(obs []harnessx.Observation) []string {
	titles := make([]string, len(obs))
	for i, o := range obs {
		titles[i] = o.Title
	}
	return titles
}

func TestDelimiterMapper_GatedOffWithoutAggressive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	summary, err := newDelimiterEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDDelimiterMapper, "root")
	require.True(t, ok)
	assert.False(t, res.Skipped)
	assert.Empty(t, res.Observations)
}

// TestDelimiterMapper_DetectsOriginOnlyDelimiter simulates an origin that
// truncates its route at ';' (serving /account for anything beginning
// /account;...) with a cacheable response — a cache keying on the verbatim
// request path would store that response under the distinct /account;... URL.
func TestDelimiterMapper_DetectsOriginOnlyDelimiter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := r.URL.EscapedPath()
		if i := strings.IndexByte(route, ';'); i >= 0 {
			route = route[:i] // origin truncates its route at ';'
		}
		if route == "/account" {
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Write([]byte("secret-account-data"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 20}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "account", URL: srv.URL + "/account"}}

	summary, err := newDelimiterEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDDelimiterMapper, "account")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Contains(t, observationTitles(res.Observations), `Origin-only path delimiter ";"`)

	for _, o := range res.Observations {
		if o.Title == `Origin-only path delimiter ";"` {
			assert.Equal(t, checkbase.SeverityHigh, o.Metadata[checkbase.SeverityKey], "a cacheable origin-only delimiter is a high-severity deception surface")
		}
	}

	// The mapping must be recorded in the per-target quirk store.
	mapping, isMapping := res.Data.(cdn.TargetQuirks)
	require.True(t, isMapping)
	recorded, ok := cdn.DiscoveredQuirks.Lookup(mapping.Origin)
	require.True(t, ok)
	var found bool
	for _, d := range recorded.Delimiters {
		if d.Delimiter == ";" {
			found = true
			assert.True(t, d.OriginOnly)
			assert.True(t, d.Cacheable)
		}
	}
	assert.True(t, found, "the \";\" discrepancy should be recorded in cdn.DiscoveredQuirks")
}

// TestDelimiterMapper_SkipsWhenOriginIgnoresTrailingJunk simulates an origin
// that serves the same body for every path: the no-delimiter R1 probe already
// matches the baseline, so no delimiter can be attributed and none is reported.
func TestDelimiterMapper_SkipsWhenOriginIgnoresTrailingJunk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("same-everywhere"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 20}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "account", URL: srv.URL + "/account"}}

	summary, err := newDelimiterEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDDelimiterMapper, "account")
	require.True(t, ok)
	for _, o := range res.Observations {
		assert.NotContains(t, o.Title, "Origin-only path delimiter", "no delimiter should be attributed when the origin ignores trailing path junk")
	}
}

// TestDelimiterMapper_DetectsEncodedTraversalNormalization simulates an origin
// that percent-decodes and collapses dot-segments (so /x/..%2faccount resolves
// to /account) — the discrepancy against a cache that keys on the verbatim,
// un-normalized detour path.
func TestDelimiterMapper_DetectsEncodedTraversalNormalization(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, err := url.PathUnescape(r.URL.EscapedPath())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if path.Clean(decoded) == "/account" {
			w.Write([]byte("secret-account-data"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 20}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "account", URL: srv.URL + "/account"}}

	summary, err := newDelimiterEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDDelimiterMapper, "account")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Contains(t, observationTitles(res.Observations), "Origin normalizes encoded path traversal")

	mapping, isMapping := res.Data.(cdn.TargetQuirks)
	require.True(t, isMapping)
	require.NotNil(t, mapping.OriginNormalizesEncodedTraversal)
	assert.True(t, *mapping.OriginNormalizesEncodedTraversal)
}

// fakeCache is a minimal shared cache in front of origin: it stores every
// non-5xx response under keyFn(request) and replays it on a repeat, labelling
// each response with Cloudflare's CF-Cache-Status so the CDN is fingerprinted.
type fakeCache struct {
	origin http.Handler
	keyFn  func(*http.Request) string
	mu     sync.Mutex
	store  map[string]*httptest.ResponseRecorder
}

func newFakeCache(origin http.Handler, keyFn func(*http.Request) string) *fakeCache {
	return &fakeCache{origin: origin, keyFn: keyFn, store: map[string]*httptest.ResponseRecorder{}}
}

func (c *fakeCache) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := c.keyFn(r)
	c.mu.Lock()
	rec, hit := c.store[key]
	c.mu.Unlock()

	if !hit {
		rec = httptest.NewRecorder()
		c.origin.ServeHTTP(rec, r)
		if rec.Code < 500 {
			c.mu.Lock()
			c.store[key] = rec
			c.mu.Unlock()
		}
	}
	for k, vs := range rec.Header() {
		w.Header()[k] = vs
	}
	w.Header().Set("Server", "cloudflare")
	if hit {
		w.Header().Set("CF-Cache-Status", "HIT")
	} else {
		w.Header().Set("CF-Cache-Status", "MISS")
	}
	w.WriteHeader(rec.Code)
	w.Write(rec.Body.Bytes())
}

// verbatimKey keys on the raw request target, as a cache that applies its
// rules before normalizing does.
func verbatimKey(r *http.Request) string { return r.RequestURI }

// normalizedKey collapses dot-segments and decodes the path first, as a cache
// that normalizes before keying does.
func normalizedKey(r *http.Request) string {
	decoded, err := url.PathUnescape(r.URL.EscapedPath())
	if err != nil {
		return r.RequestURI
	}
	return path.Clean(decoded) + "?" + r.URL.RawQuery
}

// normalizingOrigin percent-decodes and cleans the path, so /x/..%2faccount and
// /x/../account both resolve to /account.
func normalizingOrigin() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, err := url.PathUnescape(r.URL.EscapedPath())
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if path.Clean(decoded) == "/account" {
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Write([]byte("secret-account-data"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	})
}

func runMapperAgainst(t *testing.T, handler http.Handler) (harnessx.Result, cdn.TargetQuirks) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 40}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "account", URL: srv.URL + "/account"}}

	summary, err := newDelimiterEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDDelimiterMapper, "account")
	require.True(t, ok)
	mapping, isMapping := res.Data.(cdn.TargetQuirks)
	require.True(t, isMapping)
	return res, mapping
}

func observationByTitle(t *testing.T, obs []harnessx.Observation, title string) harnessx.Observation {
	t.Helper()
	for _, o := range obs {
		if o.Title == title {
			return o
		}
	}
	require.Failf(t, "observation not found", "%q not in %v", title, observationTitles(obs))
	return harnessx.Observation{}
}

// TestDelimiterMapper_CacheKeysTraversalVerbatim: the origin collapses the
// detour, the cache stores it under the verbatim detour key — the
// "normalizes after cache rules" side (Cloudflare/Google Cloud/Fastly).
func TestDelimiterMapper_CacheKeysTraversalVerbatim(t *testing.T) {
	res, mapping := runMapperAgainst(t, newFakeCache(normalizingOrigin(), verbatimKey))

	assert.Equal(t, cdn.NormalizesAfterRules, mapping.CacheEncodedTraversal)
	assert.Equal(t, cdn.NormalizesAfterRules, mapping.CacheTraversal)

	o := observationByTitle(t, res.Observations, `Cache keys encoded "..%2f" traversal verbatim`)
	assert.Equal(t, checkbase.SeverityHigh, o.Metadata[checkbase.SeverityKey])
	assert.Contains(t, o.Description, "consistent with Cloudflare's documented behavior")
	o = observationByTitle(t, res.Observations, `Cache keys plain "../" traversal verbatim`)
	assert.Equal(t, checkbase.SeverityMedium, o.Metadata[checkbase.SeverityKey])

	recorded, ok := cdn.DiscoveredQuirks.Lookup(mapping.Origin)
	require.True(t, ok)
	assert.Equal(t, cdn.NormalizesAfterRules, recorded.CacheEncodedTraversal)
}

// TestDelimiterMapper_CacheNormalizesTraversalFirst: the cache collapses the
// detour onto the canonical key (CloudFront/Azure/Imperva behavior), so the
// detour is answered from the primed canonical entry.
func TestDelimiterMapper_CacheNormalizesTraversalFirst(t *testing.T) {
	res, mapping := runMapperAgainst(t, newFakeCache(normalizingOrigin(), normalizedKey))

	assert.Equal(t, cdn.NormalizesBeforeRules, mapping.CacheEncodedTraversal)
	assert.Equal(t, cdn.NormalizesBeforeRules, mapping.CacheTraversal)

	o := observationByTitle(t, res.Observations, `Cache normalizes encoded "..%2f" traversal before applying cache rules`)
	assert.Equal(t, checkbase.SeverityInfo, o.Metadata[checkbase.SeverityKey])
	assert.Contains(t, o.Description, "differs from Cloudflare's documented behavior", "the fake is labelled Cloudflare but normalizes first")
	for _, title := range observationTitles(res.Observations) {
		assert.NotContains(t, title, "verbatim")
	}
}

// TestDelimiterMapper_CacheOrderUnobservableWithoutCache: the origin
// normalizes but nothing in front of it ever reports a hit, so no order is
// measured or recorded.
func TestDelimiterMapper_CacheOrderUnobservableWithoutCache(t *testing.T) {
	res, mapping := runMapperAgainst(t, normalizingOrigin())

	assert.Equal(t, cdn.NormalizationUnknown, mapping.CacheEncodedTraversal)
	assert.Equal(t, cdn.NormalizationUnknown, mapping.CacheTraversal)
	for _, title := range observationTitles(res.Observations) {
		assert.NotContains(t, title, "Cache keys")
		assert.NotContains(t, title, "Cache normalizes")
	}
}

// TestDelimiterMapper_DetectsCacheOnlyDelimiter: the cache keys on the path up
// to ';' while the origin routes on the full path (404 for /account;...), so a
// delimited request poisons the undelimited entry.
func TestDelimiterMapper_DetectsCacheOnlyDelimiter(t *testing.T) {
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() == "/account" {
			w.Write([]byte("secret-account-data"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	})
	truncAtSemicolon := func(r *http.Request) string {
		p, q, hasQuery := strings.Cut(r.RequestURI, "?")
		p, _, _ = strings.Cut(p, ";")
		if hasQuery {
			return p + "?" + q
		}
		return p
	}
	res, mapping := runMapperAgainst(t, newFakeCache(origin, truncAtSemicolon))

	o := observationByTitle(t, res.Observations, `Cache-only path delimiter ";"`)
	assert.Equal(t, checkbase.SeverityHigh, o.Metadata[checkbase.SeverityKey])
	for _, title := range observationTitles(res.Observations) {
		if strings.HasPrefix(title, "Cache-only path delimiter") {
			assert.Equal(t, `Cache-only path delimiter ";"`, title, "only ';' is truncated by this cache")
		}
		assert.NotContains(t, title, "Origin-only path delimiter")
	}

	var found bool
	for _, d := range mapping.Delimiters {
		if d.Delimiter == ";" {
			found = true
			assert.True(t, d.CacheOnly)
			assert.False(t, d.OriginOnly)
		}
	}
	assert.True(t, found)
}

// TestDelimiterMapper_NoCacheOnlyDelimiterWhenCacheKeysVerbatim: the same
// origin behind a cache that keys the full path reports nothing.
func TestDelimiterMapper_NoCacheOnlyDelimiterWhenCacheKeysVerbatim(t *testing.T) {
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() == "/account" {
			w.Write([]byte("secret-account-data"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	})
	res, mapping := runMapperAgainst(t, newFakeCache(origin, verbatimKey))

	assert.Empty(t, res.Observations)
	assert.Empty(t, mapping.Delimiters)
}
