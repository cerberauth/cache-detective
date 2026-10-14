package security_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
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
