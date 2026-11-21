package security_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/security"
)

// newDelimiterDeceptionEngine registers the full §5 chain
// DelimiterDeceptionCheck depends on (transitively), plus the delimiter
// mapper whose cdn.DiscoveredQuirks record it reads, plus itself.
func newDelimiterDeceptionEngine(t *testing.T) *harnessx.Engine {
	t.Helper()
	return newEngine(t,
		security.UnkeyedHeaderCheck,
		security.CacheDeceptionCheck,
		security.ErrorCachingCheck,
		security.ResponseSplittingCheck,
		security.CPDoSCheck,
		security.DelimiterMapperCheck,
		security.DelimiterDeceptionCheck,
	)
}

// TestDelimiterDeceptionCheck_DetectsConfirmedDelimiter simulates an origin
// that truncates its route at ";" (the same origin-only delimiter pattern
// TestDelimiterMapper_DetectsOriginOnlyDelimiter confirms gets recorded in
// cdn.DiscoveredQuirks) and checks that DelimiterDeceptionCheck then probes
// that confirmed delimiter with a static-looking suffix and reports the
// resulting deception.
func TestDelimiterDeceptionCheck_DetectsConfirmedDelimiter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := r.URL.EscapedPath()
		if i := strings.IndexByte(route, ';'); i >= 0 {
			route = route[:i] // origin truncates its route at ";"
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

	// A bearer token, so the probed request is authenticated — the finding
	// is reported only once the content it would store is confirmed
	// private, same gating as the classic-WCD check.
	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 40, BearerToken: "test-session-token"}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "account", URL: srv.URL + "/account"}}

	summary, err := newDelimiterDeceptionEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDDelimiterDeception, "account")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "Cache deception via confirmed origin delimiter", res.Observations[0].Title)
	assert.Contains(t, res.Observations[0].Evidence, ";")
}

// TestDelimiterDeceptionCheck_SkipsWhenNoDelimiterConfirmed simulates an
// origin that ignores every delimiter candidate (none get recorded as
// origin-only in cdn.DiscoveredQuirks) and checks that the check doesn't
// run any probes at all rather than falling back to a blind guess.
func TestDelimiterDeceptionCheck_SkipsWhenNoDelimiterConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("same-everywhere"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 40}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "account", URL: srv.URL + "/account"}}

	summary, err := newDelimiterDeceptionEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDDelimiterDeception, "account")
	require.True(t, ok)
	assert.Empty(t, res.Observations)
}

// TestDelimiterDeceptionCheck_GatedOffWithoutAggressive checks that the
// check is a no-op without --aggressive, same as every other §5 check.
func TestDelimiterDeceptionCheck_GatedOffWithoutAggressive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "account", URL: srv.URL + "/account"}}

	summary, err := newDelimiterDeceptionEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDDelimiterDeception, "account")
	require.True(t, ok)
	assert.False(t, res.Skipped)
	assert.Empty(t, res.Observations)
}
