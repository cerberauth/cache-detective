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
	"github.com/cerberauth/cache-detective/cache/checks/security"
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
	// cacheability.Def depends on the full §5 security-check chain — see
	// cacheability.Def's DependsOn comment.
	require.NoError(t, engine.Register(
		checkbase.DiscoveryCheck,
		security.UnkeyedHeaderCheck, security.CacheDeceptionCheck, security.ErrorCachingCheck, security.ResponseSplittingCheck, security.CPDoSCheck,
		cacheability.Check, livestate.Check,
	))

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
	// cacheability.Def depends on the full §5 security-check chain — see
	// cacheability.Def's DependsOn comment.
	require.NoError(t, engine.Register(
		checkbase.DiscoveryCheck,
		security.UnkeyedHeaderCheck, security.CacheDeceptionCheck, security.ErrorCachingCheck, security.ResponseSplittingCheck, security.CPDoSCheck,
		cacheability.Check, livestate.Check,
	))

	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDLiveState, "root")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "Cacheable response is not actually being cached", res.Observations[0].Title)
}

// runHitAfterFirst scans a server whose first request is a cache MISS and
// every later one a HIT, answering with status and the given Cache-Control
// (if any), and returns the live-state result.
func runHitAfterFirst(t *testing.T, status int, cacheControl string) harnessx.Result {
	t.Helper()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&n, 1) == 1 {
			w.Header().Set("X-Cache", "MISS")
		} else {
			w.Header().Set("X-Cache", "HIT")
		}
		w.Header().Set("Server", "Fastly")
		if cacheControl != "" {
			w.Header().Set("Cache-Control", cacheControl)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), RequestCount: 3}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := harnessx.New()
	require.NoError(t, engine.Register(
		checkbase.DiscoveryCheck,
		security.UnkeyedHeaderCheck, security.CacheDeceptionCheck, security.ErrorCachingCheck, security.ResponseSplittingCheck, security.CPDoSCheck,
		cacheability.Check, livestate.Check,
	))
	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDLiveState, "root")
	require.True(t, ok)
	return res
}

// TestCheck_HeuristicallyCachedErrorStatus: a 500 with no freshness is not
// cacheable by default (RFC 9110 §15.1), so a HIT can only be the cache
// inventing a lifetime for it.
func TestCheck_HeuristicallyCachedErrorStatus(t *testing.T) {
	res := runHitAfterFirst(t, http.StatusInternalServerError, "")
	require.Len(t, res.Observations, 1)
	assert.Equal(t, "Response with a non-cacheable status is being served from cache", res.Observations[0].Title)
	assert.Equal(t, checkbase.SeverityMedium, res.Observations[0].Metadata[checkbase.SeverityKey])
	assert.Contains(t, res.Observations[0].Evidence, "status=500")
}

// TestCheck_NoStoreServedFromCacheKeepsGenericFinding: with an explicit
// no-store it is the cache disobeying a directive, not inventing a lifetime
// for an unlisted status, so the status-specific wording would be wrong.
func TestCheck_NoStoreServedFromCacheKeepsGenericFinding(t *testing.T) {
	res := runHitAfterFirst(t, http.StatusInternalServerError, "no-store")
	require.Len(t, res.Observations, 1)
	assert.Equal(t, "Non-cacheable response is being served from cache", res.Observations[0].Title)
}

func TestCheck_CacheableStatusHitNotFlagged(t *testing.T) {
	res := runHitAfterFirst(t, http.StatusOK, "")
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
