package varykey_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/security"
	"github.com/cerberauth/cache-detective/cache/checks/varykey"
)

// securityChain is every §5 check varykey.Def transitively depends on (see
// its DependsOn doc comment), registered alongside it so harnessx can
// resolve the dependency graph in tests.
var securityChain = []harnessx.Check{
	security.UnkeyedHeaderCheck,
	security.CacheDeceptionCheck,
	security.ErrorCachingCheck,
	security.ResponseSplittingCheck,
	security.CPDoSCheck,
}

func TestCheck_UndeclaredUserAgentKeying(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Vary header declared, but the body reflects User-Agent —
		// an undeclared cache-key input.
		w.Write([]byte("ua=" + r.Header.Get("User-Agent")))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := harnessx.New()
	require.NoError(t, engine.Register(append([]harnessx.Check{checkbase.DiscoveryCheck, varykey.Check}, securityChain...)...))

	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)
	assert.Equal(t, 0, summary.Failed)

	res, ok := findResult(summary, checkbase.CheckIDVaryKey, "root")
	require.True(t, ok)
	data, ok := harnessx.DataAs[varykey.Result](res)
	require.True(t, ok)

	var found bool
	for _, p := range data.Probes {
		if p.Dimension == "user-agent" {
			found = true
			assert.True(t, p.Keyed)
			assert.False(t, p.Declared)
		}
	}
	assert.True(t, found)
	assert.NotEmpty(t, res.Observations)
}

func TestCheck_DeclaredVaryWithNoEffect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Accept-Encoding")
		w.Write([]byte("static"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := harnessx.New()
	require.NoError(t, engine.Register(append([]harnessx.Check{checkbase.DiscoveryCheck, varykey.Check}, securityChain...)...))

	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDVaryKey, "root")
	require.True(t, ok)
	var found bool
	for _, o := range res.Observations {
		if o.Title == "Declared Vary dimension has no observed effect: accept-encoding" {
			found = true
		}
	}
	assert.True(t, found)
}

// runVaryKey scans handler's server with pctx and returns the vary-key result.
func runVaryKey(t *testing.T, pctx checkbase.ProbeCtx, handler http.HandlerFunc) harnessx.Result {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}
	engine := harnessx.New()
	require.NoError(t, engine.Register(append([]harnessx.Check{checkbase.DiscoveryCheck, varykey.Check}, securityChain...)...))
	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDVaryKey, "root")
	require.True(t, ok)
	return res
}

// credentialCache simulates an origin that serves 2xx content only to
// callers presenting credentials, behind a cache that stores those responses
// under keyOf(r) — never including Authorization.
func credentialCache(keyOf func(*http.Request) string) http.HandlerFunc {
	var mu sync.Mutex
	store := map[string]string{}
	return func(w http.ResponseWriter, r *http.Request) {
		key := keyOf(r)
		mu.Lock()
		cached, hit := store[key]
		mu.Unlock()
		if hit {
			w.Header().Set("X-Cache", "HIT")
			_, _ = w.Write([]byte(cached))
			return
		}
		w.Header().Set("X-Cache", "MISS")
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body := "private data for " + r.Header.Get("Authorization")
		mu.Lock()
		store[key] = body
		mu.Unlock()
		_, _ = w.Write([]byte(body))
	}
}

func credentialLeakTitles(res harnessx.Result) []string {
	var titles []string
	for _, o := range res.Observations {
		titles = append(titles, o.Title)
	}
	return titles
}

const credentialLeakTitle = "Authenticated response served to unauthenticated request"

// TestCheck_CacheIgnoringCredentialsLeaksToAnonymous: the cache keys on the
// full URL but not on Authorization, so the credential-less request is served
// the first caller's response — while the same credential-less request on a
// cache-buster URL (a different key) is refused by the origin.
func TestCheck_CacheIgnoringCredentialsLeaksToAnonymous(t *testing.T) {
	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), BearerToken: "victim-token"}).WithDefaults()
	res := runVaryKey(t, pctx, credentialCache(func(r *http.Request) string { return r.URL.RequestURI() }))

	var found bool
	for _, o := range res.Observations {
		if o.Title == credentialLeakTitle {
			found = true
			assert.Equal(t, checkbase.SeverityCritical, o.Metadata[checkbase.SeverityKey])
			assert.NotContains(t, o.Evidence, "victim-token")
		}
	}
	assert.True(t, found, "got %v", credentialLeakTitles(res))
}

// TestCheck_CacheIgnoringQueryAndCredentialsIsProbable: the cache also
// ignores the query string, so the cache-buster can't isolate a fresh entry —
// the origin's behavior for anonymous callers can't be seen, but both
// credential-less requests were cache HITs on the authenticated body.
func TestCheck_CacheIgnoringQueryAndCredentialsIsProbable(t *testing.T) {
	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), BearerToken: "victim-token"}).WithDefaults()
	res := runVaryKey(t, pctx, credentialCache(func(r *http.Request) string { return r.URL.Path }))

	var found bool
	for _, o := range res.Observations {
		if o.Title == credentialLeakTitle {
			found = true
			assert.Equal(t, checkbase.SeverityHigh, o.Metadata[checkbase.SeverityKey])
		}
	}
	assert.True(t, found, "got %v", credentialLeakTitles(res))
}

func TestCheck_CacheKeyedOnCredentialsNotFlagged(t *testing.T) {
	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), BearerToken: "victim-token"}).WithDefaults()
	res := runVaryKey(t, pctx, credentialCache(func(r *http.Request) string {
		return r.URL.RequestURI() + "|" + r.Header.Get("Authorization")
	}))
	assert.NotContains(t, credentialLeakTitles(res), credentialLeakTitle)
}

// TestCheck_PublicContentNotFlaggedAsCredentialLeak: an origin that serves the
// same body to everyone proves nothing about the cache, even though the
// credential-less response matches the authenticated one.
func TestCheck_PublicContentNotFlaggedAsCredentialLeak(t *testing.T) {
	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), BearerToken: "victim-token"}).WithDefaults()
	res := runVaryKey(t, pctx, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache", "MISS")
		_, _ = w.Write([]byte("public page"))
	})
	assert.NotContains(t, credentialLeakTitles(res), credentialLeakTitle)
}

func TestCheck_NoCredentialsConfiguredSkipsCredentialProbe(t *testing.T) {
	var busterRequests atomic.Int64
	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	res := runVaryKey(t, pctx, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("cd_cachebuster") {
			busterRequests.Add(1)
		}
		w.Header().Set("X-Cache", "HIT")
		_, _ = w.Write([]byte("page"))
	})
	assert.NotContains(t, credentialLeakTitles(res), credentialLeakTitle)
	// The credential probe is the only vary-key request that uses a
	// cache-buster; with no credentials to strip it must not run at all.
	assert.Zero(t, busterRequests.Load())
}

// TestCheck_CookieCredentialsAreStrippedToo covers the Vary-misconfiguration
// shape: the response depends on a session cookie, the cache keys on the URL
// only.
func TestCheck_CookieCredentialsAreStrippedToo(t *testing.T) {
	var mu sync.Mutex
	store := map[string]string{}
	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Cookies: []checkbase.Cookie{{Name: "session", Value: "alice"}}}).WithDefaults()
	res := runVaryKey(t, pctx, func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.RequestURI()
		mu.Lock()
		cached, hit := store[key]
		mu.Unlock()
		if hit {
			w.Header().Set("X-Cache", "HIT")
			_, _ = w.Write([]byte(cached))
			return
		}
		w.Header().Set("X-Cache", "MISS")
		greeting := "Hello, guest"
		if c, err := r.Cookie("session"); err == nil {
			greeting = "Hello, " + c.Value
		}
		mu.Lock()
		store[key] = greeting
		mu.Unlock()
		_, _ = w.Write([]byte(greeting))
	})
	assert.Contains(t, credentialLeakTitles(res), credentialLeakTitle)
}

func findResult(summary harnessx.ScanSummary, id harnessx.CheckID, resourceID string) (harnessx.Result, bool) {
	for _, r := range summary.Results {
		if r.CheckID == id && r.ResourceID == resourceID {
			return r, true
		}
	}
	return harnessx.Result{}, false
}
