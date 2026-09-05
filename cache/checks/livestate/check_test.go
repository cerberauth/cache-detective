package livestate_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
	"github.com/cerberauth/cache-detective/cache/checks/livestate"
)

func TestCheck_MissThenHit(t *testing.T) {
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("ETag", `"v1"`)
		if atomic.AddInt64(&n, 1) <= 2 {
			// The first request is consumed by cacheability.Check's own
			// probe (it runs before livestate.Check, per DependsOn); the
			// second is livestate's first sample, kept a MISS so the
			// first-miss-then-hit pattern is still observed within the
			// live-state check's own samples.
			w.Header().Set("X-Cache", "MISS")
		} else {
			w.Header().Set("X-Cache", "HIT")
			w.Header().Set("Age", "5")
		}
		w.Header().Set("Server", "Fastly")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), RequestCount: 3}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := harnessx.New()
	require.NoError(t, engine.Register(checkbase.DiscoveryCheck, cacheability.Check, livestate.Check))

	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)
	assert.Equal(t, 0, summary.Failed)

	res, ok := findResult(summary, checkbase.CheckIDLiveState, "root")
	require.True(t, ok)
	analysis, ok := harnessx.DataAs[livestate.AnalysisResult](res)
	require.True(t, ok)
	assert.True(t, analysis.FirstMissThenHit)
	assert.Equal(t, 2, analysis.HitCount)
	assert.Equal(t, 1, analysis.MissCount)
}

func TestCheck_CacheableButNeverHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("X-Cache", "MISS")
		w.Header().Set("Server", "Fastly")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), RequestCount: 2}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := harnessx.New()
	require.NoError(t, engine.Register(checkbase.DiscoveryCheck, cacheability.Check, livestate.Check))

	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDLiveState, "root")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "Cacheable response is not actually being cached", res.Observations[0].Title)
}

func findResult(summary harnessx.ScanSummary, id harnessx.CheckID, resourceID string) (harnessx.Result, bool) {
	for _, r := range summary.Results {
		if r.CheckID == id && r.ResourceID == resourceID {
			return r, true
		}
	}
	return harnessx.Result{}, false
}
