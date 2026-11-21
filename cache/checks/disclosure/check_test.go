package disclosure_test

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
	"github.com/cerberauth/cache-detective/cache/checks/disclosure"
	"github.com/cerberauth/cache-detective/cache/checks/livestate"
	"github.com/cerberauth/cache-detective/cache/checks/security"
)

// newDisclosureEngine registers discovery, the full §5 security-check
// chain (cacheability.Def transitively depends on it — see its DependsOn
// comment), cacheability, livestate, and the disclosure sweep itself.
func newDisclosureEngine(t *testing.T) *harnessx.Engine {
	t.Helper()
	engine := harnessx.New()
	require.NoError(t, engine.Register(
		checkbase.DiscoveryCheck,
		security.UnkeyedHeaderCheck, security.CacheDeceptionCheck, security.ErrorCachingCheck, security.ResponseSplittingCheck, security.CPDoSCheck,
		cacheability.Check, livestate.Check, disclosure.Check,
	))
	return engine
}

func findResult(summary harnessx.ScanSummary, id harnessx.CheckID, resourceID string) (harnessx.Result, bool) {
	for _, r := range summary.Results {
		if r.CheckID == id && r.ResourceID == resourceID {
			return r, true
		}
	}
	return harnessx.Result{}, false
}

// TestCheck_FlagsLiveSessionDisclosure simulates a resource that mints a
// session cookie and is actually being served from a shared cache (a live
// HIT, not just a theoretical misconfiguration per its declared headers).
func TestCheck_FlagsLiveSessionDisclosure(t *testing.T) {
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("Set-Cookie", "session=abc123")
		if atomic.AddInt64(&n, 1) <= 2 {
			// Request 1 is cacheability.Check's own probe; request 2 is
			// live-state's first sample — both kept a MISS so the
			// first-miss-then-hit pattern is still observed.
			w.Header().Set("X-Cache", "MISS")
		} else {
			w.Header().Set("X-Cache", "HIT")
		}
		w.Write([]byte("welcome back"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), RequestCount: 3}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	summary, err := newDisclosureEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)
	assert.Equal(t, 0, summary.Failed)

	res, ok := findResult(summary, checkbase.CheckIDInfoDisclosure, "root")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "Shared cache is serving session-specific content", res.Observations[0].Title)
	assert.Equal(t, checkbase.SeverityCritical, res.Observations[0].Metadata[checkbase.SeverityKey])
}

// TestCheck_FlagsSensitiveJSONMissingNoStore simulates an unauthenticated
// JSON API response carrying PII without no-store/no-cache — a disclosure
// AuthDef/SessionDef wouldn't catch, since the request carries no
// credentials and the response sets no Set-Cookie.
func TestCheck_FlagsSensitiveJSONMissingNoStore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Write([]byte(`{"email": "user@example.com"}`))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "profile", URL: srv.URL + "/profile"}}

	summary, err := newDisclosureEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDInfoDisclosure, "profile")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "Sensitive JSON response missing no-store/no-cache", res.Observations[0].Title)
	assert.Equal(t, checkbase.SeverityHigh, res.Observations[0].Metadata[checkbase.SeverityKey])
}

// TestCheck_DoesNotFlagProtectedSensitiveJSON simulates the same PII-bearing
// JSON response, but correctly marked no-store/no-cache — no finding.
func TestCheck_DoesNotFlagProtectedSensitiveJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache")
		w.Write([]byte(`{"email": "user@example.com"}`))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "profile", URL: srv.URL + "/profile"}}

	summary, err := newDisclosureEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDInfoDisclosure, "profile")
	require.True(t, ok)
	assert.Empty(t, res.Observations)
}

// TestCheck_DoesNotFlagGenericPublicContent simulates a plain, non-JSON,
// non-session, cacheable response — no finding.
func TestCheck_DoesNotFlagGenericPublicContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Write([]byte("welcome to our public homepage"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "home", URL: srv.URL + "/home"}}

	summary, err := newDisclosureEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDInfoDisclosure, "home")
	require.True(t, ok)
	assert.Empty(t, res.Observations)
}
