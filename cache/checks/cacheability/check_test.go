package cacheability_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runChecks(t *testing.T, pctx *checkbase.ProbeCtx, target string) harnessx.ScanSummary {
	t.Helper()
	engine := harnessx.New()
	require.NoError(t, engine.Register(checkbase.DiscoveryCheck, cacheability.Check, cacheability.AuthCheck))

	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: target}}
	summary, err := engine.Run(context.Background(), harnessx.Target{URL: target, Data: pctx})
	require.NoError(t, err)
	return summary
}

func TestCheck_CacheableResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	summary := runChecks(t, &pctx, srv.URL)

	assert.Equal(t, 0, summary.Failed)
	res, ok := findResult(summary, checkbase.CheckIDCacheability, "root")
	require.True(t, ok)
	analysis, ok := harnessx.DataAs[cacheability.AnalysisResult](res)
	require.True(t, ok)
	assert.True(t, analysis.Cacheable)
	assert.Empty(t, analysis.Findings)
}

func TestCheck_AuthenticatedCacheableFlagsFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), BearerToken: "secret-token"}).WithDefaults()
	summary := runChecks(t, &pctx, srv.URL)

	res, ok := findResult(summary, checkbase.CheckIDAuthCacheable, "root")
	require.True(t, ok)
	require.Len(t, res.Observations, 1)
	assert.Equal(t, "Authenticated response marked cacheable", res.Observations[0].Title)
}

func TestCheck_AuthenticatedPrivateNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, max-age=600")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), BearerToken: "secret-token"}).WithDefaults()
	summary := runChecks(t, &pctx, srv.URL)

	res, ok := findResult(summary, checkbase.CheckIDAuthCacheable, "root")
	require.True(t, ok)
	assert.Empty(t, res.Observations)
}

func findResult(summary harnessx.ScanSummary, id harnessx.CheckID, resourceID string) (harnessx.Result, bool) {
	for _, r := range summary.Results {
		if r.CheckID == id && r.ResourceID == resourceID {
			return r, true
		}
	}
	return harnessx.Result{}, false
}
