package cacheability_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
	"github.com/cerberauth/cache-detective/cache/checks/security"
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runChecks(t *testing.T, pctx *checkbase.ProbeCtx, target string) harnessx.ScanSummary {
	t.Helper()
	engine := harnessx.New()
	// cacheability.Def depends on the full §5 security-check chain (see its
	// DependsOn doc comment), so every check in that chain must be
	// registered alongside it for harnessx to resolve the dependency graph.
	require.NoError(t, engine.Register(
		checkbase.DiscoveryCheck,
		security.UnkeyedHeaderCheck, security.CacheDeceptionCheck, security.ErrorCachingCheck, security.ResponseSplittingCheck, security.CPDoSCheck,
		cacheability.Check, cacheability.AuthCheck, cacheability.SessionCheck,
	))

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
		// No must-revalidate/public/s-maxage: RFC 9111 §3.5 gives a shared
		// cache no explicit permission to store this despite Authorization.
		w.Header().Set("Cache-Control", "max-age=600")
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
	assert.Equal(t, checkbase.SeverityHigh, res.Observations[0].Metadata[checkbase.SeverityKey])
}

func TestCheck_AuthProfileOnlyCacheableFlagsFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=600")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// No top-level BearerToken/Cookies, so WithDefaults leaves Authenticated
	// false — credentials come only from a per-origin AuthProfiles entry.
	pctx := (&checkbase.ProbeCtx{
		Probe: probe.New(),
		AuthProfiles: map[string]checkbase.AuthProfile{
			serverOrigin(t, srv.URL): {Cookies: []checkbase.Cookie{{Name: "session", Value: "abc"}}},
		},
	}).WithDefaults()
	summary := runChecks(t, &pctx, srv.URL)

	res, ok := findResult(summary, checkbase.CheckIDAuthCacheable, "root")
	require.True(t, ok)
	require.Len(t, res.Observations, 1)
	assert.Equal(t, "Authenticated response marked cacheable", res.Observations[0].Title)
}

func TestCheck_AuthenticatedCacheableWithSensitiveBodyEscalatesSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=600")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"email":"user@example.com"}`))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), BearerToken: "secret-token"}).WithDefaults()
	summary := runChecks(t, &pctx, srv.URL)

	res, ok := findResult(summary, checkbase.CheckIDAuthCacheable, "root")
	require.True(t, ok)
	require.Len(t, res.Observations, 1)
	assert.Equal(t, checkbase.SeverityCritical, res.Observations[0].Metadata[checkbase.SeverityKey])
}

func TestCheck_AuthenticatedPublicExplicitlyPermittedNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// public is one of the RFC 9111 §3.5 opt-in directives.
		w.Header().Set("Cache-Control", "public, max-age=600")
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

func TestCheck_CacheableSetCookieFlagsSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "live-session-value", HttpOnly: true})
		_, _ = w.Write([]byte("dashboard"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	summary := runChecks(t, &pctx, srv.URL)

	res, ok := findResult(summary, checkbase.CheckIDSessionCacheable, "root")
	require.True(t, ok)
	require.Len(t, res.Observations, 1)
	assert.Equal(t, "Cacheable response sets a cookie", res.Observations[0].Title)
	assert.Equal(t, checkbase.SeverityHigh, res.Observations[0].Metadata[checkbase.SeverityKey], "a session-looking cookie name escalates past the base severity")
	assert.Contains(t, res.Observations[0].Evidence, "session")
	assert.NotContains(t, res.Observations[0].Evidence, "live-session-value", "the cookie value must never be echoed into a report")
}

func TestCheck_CacheableSetCookieWithTokenBodyIsCritical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"})
		_, _ = w.Write([]byte(`{"user": "u1", "csrf_token": "tok-123"}`))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	summary := runChecks(t, &pctx, srv.URL)

	res, ok := findResult(summary, checkbase.CheckIDSessionCacheable, "root")
	require.True(t, ok)
	require.Len(t, res.Observations, 1)
	assert.Equal(t, checkbase.SeverityCritical, res.Observations[0].Metadata[checkbase.SeverityKey])
}

func TestCheck_NonSessionCookieIsMediumSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "lang", Value: "en"})
		_, _ = w.Write([]byte("page"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	summary := runChecks(t, &pctx, srv.URL)

	res, ok := findResult(summary, checkbase.CheckIDSessionCacheable, "root")
	require.True(t, ok)
	require.Len(t, res.Observations, 1)
	assert.Equal(t, checkbase.SeverityMedium, res.Observations[0].Metadata[checkbase.SeverityKey])
}

func TestCheck_SetCookieNotCacheableNotFlagged(t *testing.T) {
	for name, cc := range map[string]string{"private": "private", "no-store": "no-store"} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", cc)
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"})
				_, _ = w.Write([]byte("dashboard"))
			}))
			defer srv.Close()

			pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
			summary := runChecks(t, &pctx, srv.URL)

			res, ok := findResult(summary, checkbase.CheckIDSessionCacheable, "root")
			require.True(t, ok)
			assert.Empty(t, res.Observations)
		})
	}
}

func TestCheck_NoCookieNotFlaggedBySession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("page"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	summary := runChecks(t, &pctx, srv.URL)

	res, ok := findResult(summary, checkbase.CheckIDSessionCacheable, "root")
	require.True(t, ok)
	assert.Empty(t, res.Observations)
}

// TestCheck_AuthenticatedSetCookieReportedOnlyByAuthCheck: AuthCheck already
// reports (and escalates on) an authenticated cacheable response carrying
// Set-Cookie; a second finding for the same defect would be noise.
func TestCheck_AuthenticatedSetCookieReportedOnlyByAuthCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"})
		_, _ = w.Write([]byte("dashboard"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), BearerToken: "secret-token"}).WithDefaults()
	summary := runChecks(t, &pctx, srv.URL)

	auth, ok := findResult(summary, checkbase.CheckIDAuthCacheable, "root")
	require.True(t, ok)
	assert.Len(t, auth.Observations, 1)
	session, ok := findResult(summary, checkbase.CheckIDSessionCacheable, "root")
	require.True(t, ok)
	assert.Empty(t, session.Observations)
}

func serverOrigin(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return u.Scheme + "://" + u.Host
}

func findResult(summary harnessx.ScanSummary, id harnessx.CheckID, resourceID string) (harnessx.Result, bool) {
	for _, r := range summary.Results {
		if r.CheckID == id && r.ResourceID == resourceID {
			return r, true
		}
	}
	return harnessx.Result{}, false
}
