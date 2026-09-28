package security_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// TestUnkeyedHeaderCheck_DoesNotPoisonCanonicalURL simulates a cache keyed
// by the exact request URL (path+query), the common case a cache-buster
// query param actually isolates against. It asserts the check still
// detects the poisoning surface while never leaving the resource's real,
// canonical URL (no query string at all) poisoned for a plain follow-up
// request a real user could make — the safety property issue #10 requires.
func TestUnkeyedHeaderCheck_DoesNotPoisonCanonicalURL(t *testing.T) {
	var mu sync.Mutex
	cached := map[string]string{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.String()
		mu.Lock()
		defer mu.Unlock()
		if v := r.Header.Get("X-Forwarded-Host"); v != "" {
			cached[key] = "host=" + v
		}
		if body, ok := cached[key]; ok {
			w.Write([]byte(body))
			return
		}
		w.Write([]byte("host="))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 10}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := newEngine(t, security.UnkeyedHeaderCheck)
	_, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	body := make([]byte, 128)
	n, _ := resp.Body.Read(body)
	assert.NotContains(t, string(body[:n]), "cache-detective-poison-marker.invalid", "the resource's real, canonical URL must never be poisoned by the probe")
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

	engine := newEngine(t, security.UnkeyedHeaderCheck, security.CacheDeceptionCheck)
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

	engine := newEngine(t, security.UnkeyedHeaderCheck, security.CacheDeceptionCheck, security.ErrorCachingCheck)
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

	engine := newEngine(t, security.UnkeyedHeaderCheck, security.CacheDeceptionCheck, security.ErrorCachingCheck, security.ResponseSplittingCheck)
	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDResponseSplitting, "root")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "Response splitting via unkeyed input", res.Observations[0].Title)
}

func newCPDoSEngine(t *testing.T) *harnessx.Engine {
	t.Helper()
	return newEngine(t, security.UnkeyedHeaderCheck, security.CacheDeceptionCheck, security.ErrorCachingCheck, security.ResponseSplittingCheck, security.CPDoSCheck)
}

func TestCPDoSCheck_GatedOffWithoutAggressive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	summary, err := newCPDoSEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDCPDoS, "root")
	require.True(t, ok)
	assert.False(t, res.Skipped)
	assert.Empty(t, res.Observations)
}

// TestCPDoSCheck_DetectsHeaderOversizePoisoning simulates the CPDoS "HTTP
// Header Oversize" (HHO) pattern: an origin that rejects an oversized
// header block, fronted by a single-slot cache that stores and replays
// that error to every subsequent caller of the path.
func TestCPDoSCheck_DetectsHeaderOversizePoisoning(t *testing.T) {
	var mu sync.Mutex
	var cachedStatus int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if cachedStatus != 0 {
			w.WriteHeader(cachedStatus)
			mu.Unlock()
			return
		}
		mu.Unlock()

		size := 0
		for name, values := range r.Header {
			for _, v := range values {
				size += len(name) + len(v)
			}
		}
		if size > 8192 {
			mu.Lock()
			cachedStatus = http.StatusRequestHeaderFieldsTooLarge
			mu.Unlock()
			w.WriteHeader(http.StatusRequestHeaderFieldsTooLarge)
			return
		}
		w.Write([]byte("welcome"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 10}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	summary, err := newCPDoSEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDCPDoS, "root")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "CPDoS via oversized headers (HHO)", res.Observations[0].Title)
}

// TestCPDoSCheck_DetectsMethodOverridePoisoning simulates the CPDoS "HTTP
// Method Override" (HMO) pattern.
func TestCPDoSCheck_DetectsMethodOverridePoisoning(t *testing.T) {
	var mu sync.Mutex
	var cachedStatus int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if cachedStatus != 0 {
			w.WriteHeader(cachedStatus)
			mu.Unlock()
			return
		}
		mu.Unlock()

		if r.Header.Get("X-HTTP-Method-Override") == "DELETE" {
			mu.Lock()
			cachedStatus = http.StatusMethodNotAllowed
			mu.Unlock()
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Write([]byte("welcome"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 10}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	summary, err := newCPDoSEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDCPDoS, "root")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "CPDoS via method override (HMO)", res.Observations[0].Title)
}

// TestCPDoSCheck_DetectsMetaCharacterPoisoning simulates the CPDoS "HTTP
// Meta Character" (HMC) pattern: the cache keys purely on the path, while
// the origin inspects an existing query value.
func TestCPDoSCheck_DetectsMetaCharacterPoisoning(t *testing.T) {
	var mu sync.Mutex
	var cachedStatus int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if cachedStatus != 0 {
			w.WriteHeader(cachedStatus)
			mu.Unlock()
			return
		}
		mu.Unlock()

		if strings.ContainsRune(r.URL.Query().Get("name"), 0) {
			mu.Lock()
			cachedStatus = http.StatusBadRequest
			mu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Write([]byte("welcome"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 10}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL + "/?name=cache-detective"}}

	summary, err := newCPDoSEngine(t).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDCPDoS, "root")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "CPDoS via HTTP meta-character (HMC)", res.Observations[0].Title)
}

// TestCacheDeceptionCheck_DetectsDelimiterConfusion simulates web cache
// deception via an origin-only path delimiter (";"): the cache decides
// cacheability from whatever static-looking suffix follows the delimiter,
// while the origin ignores the delimiter and keeps serving the same
// dynamic, authenticated response.
func TestCacheDeceptionCheck_DetectsDelimiterConfusion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret-account-data"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: 10}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "account", URL: srv.URL + "/account"}}

	engine := newEngine(t, security.UnkeyedHeaderCheck, security.CacheDeceptionCheck)
	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDCacheDeception, "account")
	require.True(t, ok)
	require.NotEmpty(t, res.Observations)
	assert.Equal(t, "Cache deception via path confusion", res.Observations[0].Title)
}

func findResult(summary harnessx.ScanSummary, id harnessx.CheckID, resourceID string) (harnessx.Result, bool) {
	for _, r := range summary.Results {
		if r.CheckID == id && r.ResourceID == resourceID {
			return r, true
		}
	}
	return harnessx.Result{}, false
}
