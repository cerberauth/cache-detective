package staleserving_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
	"github.com/cerberauth/cache-detective/cache/checks/security"
	"github.com/cerberauth/cache-detective/cache/checks/staleserving"
)

func runCheck(t *testing.T, handler http.HandlerFunc, aggressive bool) harnessx.ScanSummary {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	pctx := (&checkbase.ProbeCtx{
		Probe:              probe.New(),
		Aggressive:         aggressive,
		StaleWindowMaxWait: 5 * time.Second,
	}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := harnessx.New()
	require.NoError(t, engine.Register(
		checkbase.DiscoveryCheck,
		security.UnkeyedHeaderCheck, security.CacheDeceptionCheck, security.ErrorCachingCheck, security.ResponseSplittingCheck,
		cacheability.Check, staleserving.Check,
	))

	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)
	return summary
}

func findResult(summary harnessx.ScanSummary, id harnessx.CheckID, resourceID string) (harnessx.Result, bool) {
	for _, r := range summary.Results {
		if r.CheckID == id && r.ResourceID == resourceID {
			return r, true
		}
	}
	return harnessx.Result{}, false
}

// fakeEdgeCache is a tiny in-memory stand-in for a fronting CDN, used to
// exercise honored/not-honored stale-serving behavior deterministically in
// tests without depending on a real CDN.
type fakeEdgeCache struct {
	mu        sync.Mutex
	fetchedAt time.Time
	body      string
	honor     bool // whether it actually implements SWR/SIE, or just refetches synchronously
	maxAge    time.Duration
	swr       time.Duration
	sie       time.Duration
}

func (c *fakeEdgeCache) handler(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if c.fetchedAt.IsZero() {
		c.fetchedAt = now
		c.body = "v0"
	}
	age := now.Sub(c.fetchedAt)

	simulateError := r.Header.Get("X-Cache-Detective-Simulate-Error") != ""

	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, stale-while-revalidate=%d, stale-if-error=%d", int(c.maxAge.Seconds()), int(c.swr.Seconds()), int(c.sie.Seconds())))

	if simulateError {
		if c.honor && age < c.maxAge+c.swr+c.sie {
			w.Header().Set("Age", fmt.Sprintf("%d", int(age.Seconds())))
			_, _ = w.Write([]byte(c.body))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch {
	case age < c.maxAge:
		w.Header().Set("Age", fmt.Sprintf("%d", int(age.Seconds())))
		_, _ = w.Write([]byte(c.body))
	case age < c.maxAge+c.swr:
		if c.honor {
			w.Header().Set("Age", fmt.Sprintf("%d", int(age.Seconds())))
			_, _ = w.Write([]byte(c.body))
			// Simulate an async background revalidation completing
			// immediately, so a follow-up request sees a fresh object.
			c.fetchedAt = now
		} else {
			// Blocks on a synchronous origin refetch instead of serving
			// stale content.
			time.Sleep(300 * time.Millisecond)
			c.fetchedAt = now
			w.Header().Set("Age", "0")
			_, _ = w.Write([]byte(c.body))
		}
	default:
		c.fetchedAt = now
		w.Header().Set("Age", "0")
		_, _ = w.Write([]byte(c.body))
	}
}

func TestCheck_NoStaleDirectives_NoResult(t *testing.T) {
	summary := runCheck(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte("v0"))
	}, false)

	res, ok := findResult(summary, checkbase.CheckIDStaleServing, "root")
	require.True(t, ok)
	assert.Nil(t, res.Data)
	assert.Empty(t, res.Observations)
}

func TestCheck_StaleWhileRevalidate_Honored(t *testing.T) {
	c := &fakeEdgeCache{honor: true, maxAge: time.Second, swr: 3 * time.Second, sie: 5 * time.Second}
	summary := runCheck(t, c.handler, false)

	res, ok := findResult(summary, checkbase.CheckIDStaleServing, "root")
	require.True(t, ok)
	data, ok := harnessx.DataAs[staleserving.Result](res)
	require.True(t, ok)
	require.NotNil(t, data.SWRHonored)
	assert.True(t, *data.SWRHonored)
	for _, o := range res.Observations {
		assert.NotEqual(t, "stale-while-revalidate not honored", o.Title)
	}
}

func TestCheck_StaleWhileRevalidate_NotHonored(t *testing.T) {
	c := &fakeEdgeCache{honor: false, maxAge: time.Second, swr: 3 * time.Second, sie: 5 * time.Second}
	summary := runCheck(t, c.handler, false)

	res, ok := findResult(summary, checkbase.CheckIDStaleServing, "root")
	require.True(t, ok)
	data, ok := harnessx.DataAs[staleserving.Result](res)
	require.True(t, ok)
	require.NotNil(t, data.SWRHonored)
	assert.False(t, *data.SWRHonored)

	var found bool
	for _, o := range res.Observations {
		if o.Title == "stale-while-revalidate not honored" {
			found = true
		}
	}
	assert.True(t, found)
}

func TestCheck_StaleIfError_RequiresAggressive(t *testing.T) {
	c := &fakeEdgeCache{honor: true, maxAge: 60 * time.Second, swr: 0, sie: 60 * time.Second}
	summary := runCheck(t, c.handler, false)

	res, ok := findResult(summary, checkbase.CheckIDStaleServing, "root")
	require.True(t, ok)
	data, ok := harnessx.DataAs[staleserving.Result](res)
	require.True(t, ok)
	assert.Nil(t, data.SIEHonored)

	var found bool
	for _, o := range res.Observations {
		if o.Title == "stale-if-error confirmation requires --aggressive" {
			found = true
		}
	}
	assert.True(t, found)
}

func TestCheck_StaleIfError_Honored(t *testing.T) {
	c := &fakeEdgeCache{honor: true, maxAge: 60 * time.Second, swr: 0, sie: 60 * time.Second}
	summary := runCheck(t, c.handler, true)

	res, ok := findResult(summary, checkbase.CheckIDStaleServing, "root")
	require.True(t, ok)
	data, ok := harnessx.DataAs[staleserving.Result](res)
	require.True(t, ok)
	require.NotNil(t, data.SIEHonored)
	assert.True(t, *data.SIEHonored)
}

func TestCheck_StaleIfError_NotHonored(t *testing.T) {
	c := &fakeEdgeCache{honor: false, maxAge: 60 * time.Second, swr: 0, sie: 60 * time.Second}
	summary := runCheck(t, c.handler, true)

	res, ok := findResult(summary, checkbase.CheckIDStaleServing, "root")
	require.True(t, ok)
	data, ok := harnessx.DataAs[staleserving.Result](res)
	require.True(t, ok)
	require.NotNil(t, data.SIEHonored)
	assert.False(t, *data.SIEHonored)

	var found bool
	for _, o := range res.Observations {
		if o.Title == "stale-if-error not honored" {
			found = true
		}
	}
	assert.True(t, found)
}
