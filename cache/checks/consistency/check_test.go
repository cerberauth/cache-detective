package consistency_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
	"github.com/cerberauth/cache-detective/cache/checks/consistency"
)

func runCheck(t *testing.T, handler http.HandlerFunc) (harnessx.ScanSummary, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := harnessx.New()
	require.NoError(t, engine.Register(checkbase.DiscoveryCheck, cacheability.Check, consistency.Check))

	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)
	return summary, srv.URL
}

func TestCheck_ConditionalRequestHonored(t *testing.T) {
	summary, _ := runCheck(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Cache-Control", "public, max-age=60")
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Write([]byte("body"))
	})

	res, ok := findResult(summary, checkbase.CheckIDConsistency, "root")
	require.True(t, ok)
	data, ok := harnessx.DataAs[consistency.Result](res)
	require.True(t, ok)
	require.NotNil(t, data.ConditionalRequestHonored)
	assert.True(t, *data.ConditionalRequestHonored)
	assert.Empty(t, res.Observations)
}

func TestCheck_ConditionalRequestNotHonored(t *testing.T) {
	summary, _ := runCheck(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write([]byte("body"))
	})

	res, ok := findResult(summary, checkbase.CheckIDConsistency, "root")
	require.True(t, ok)
	data, ok := harnessx.DataAs[consistency.Result](res)
	require.True(t, ok)
	require.NotNil(t, data.ConditionalRequestHonored)
	assert.False(t, *data.ConditionalRequestHonored)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "Conditional request not honored", res.Observations[0].Title)
}

func TestCheck_RedirectWithoutExplicitFreshness(t *testing.T) {
	summary, url := runCheck(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusMovedPermanently)
	})
	_ = url

	res, ok := findResult(summary, checkbase.CheckIDConsistency, "root")
	require.True(t, ok)
	data, ok := harnessx.DataAs[consistency.Result](res)
	require.True(t, ok)
	assert.True(t, data.IsRedirect)
	assert.True(t, data.RedirectCacheable)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "Redirect cached with only heuristic freshness", res.Observations[0].Title)
}

func findResult(summary harnessx.ScanSummary, id harnessx.CheckID, resourceID string) (harnessx.Result, bool) {
	for _, r := range summary.Results {
		if r.CheckID == id && r.ResourceID == resourceID {
			return r, true
		}
	}
	return harnessx.Result{}, false
}
