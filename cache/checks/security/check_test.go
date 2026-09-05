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

func newEngine(t *testing.T, checks ...harnessx.Check) *harnessx.Engine {
	t.Helper()
	engine := harnessx.New()
	require.NoError(t, engine.Register(append([]harnessx.Check{checkbase.DiscoveryCheck}, checks...)...))
	return engine
}

func TestUnkeyedHeaderCheck_GatedOffWithoutAggressive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("host=" + r.Header.Get("X-Forwarded-Host")))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := newEngine(t, security.UnkeyedHeaderCheck)
	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	// Gated off inside Run (not via harnessx.SkipDecision — see
	// aggressiveGate's doc comment): the check still executes per-resource,
	// it just reports nothing back.
	res, ok := findResult(summary, checkbase.CheckIDUnkeyedHeader, "root")
	require.True(t, ok)
	assert.False(t, res.Skipped)
	assert.Empty(t, res.Observations)
}

func TestUnkeyedHeaderCheck_DetectsPoisoning(t *testing.T) {
	// Simulates a naive shared-cache in front of an origin that reflects
	// X-Forwarded-Host: the "cache" always serves back whatever was
	// reflected on the very first request for the path, regardless of
	// headers on later requests.
	var cached string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cached == "" {
			cached = "host=" + r.Header.Get("X-Forwarded-Host")
		}
		w.Write([]byte(cached))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 10}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := newEngine(t, security.UnkeyedHeaderCheck)
	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDUnkeyedHeader, "root")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Contains(t, res.Observations[0].Title, "Unkeyed header injection")
}

func TestCacheDeceptionCheck_DetectsPathConfusion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any path under /account is served the same "authenticated"
		// payload with cacheable headers — simulating a origin/CDN combo
		// vulnerable to static-extension path confusion.
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write([]byte("secret-account-data"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 10}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "account", URL: srv.URL + "/account"}}

	engine := newEngine(t, security.CacheDeceptionCheck)
	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDCacheDeception, "account")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "Cache deception via path confusion", res.Observations[0].Title)
}

func TestErrorCachingCheck_FlagsCacheableError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			w.Header().Set("Cache-Control", "public, max-age=300")
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 10}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := newEngine(t, security.ErrorCachingCheck)
	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDErrorCaching, "root")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "Error response is cacheable", res.Observations[0].Title)
}

func TestResponseSplittingCheck_DetectsInjectedHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		if idx := strings.Index(xfh, "%0d%0a"); idx >= 0 {
			// Simulate a vulnerable origin that decodes and reflects the
			// header verbatim into the response.
			rest := xfh[idx+len("%0d%0a"):]
			name, value, ok := strings.Cut(rest, ":%20")
			if ok {
				w.Header().Set(name, value)
			}
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 10}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := newEngine(t, security.UnkeyedHeaderCheck, security.ResponseSplittingCheck)
	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDResponseSplitting, "root")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "Response splitting via unkeyed input", res.Observations[0].Title)
}

func findResult(summary harnessx.ScanSummary, id harnessx.CheckID, resourceID string) (harnessx.Result, bool) {
	for _, r := range summary.Results {
		if r.CheckID == id && r.ResourceID == resourceID {
			return r, true
		}
	}
	return harnessx.Result{}, false
}
