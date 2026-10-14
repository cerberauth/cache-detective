package security_test

import (
	"context"
	"io"
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

// newChainEngine registers the §5 poison chain every tail-of-chain check
// depends on (transitively, via CPDoSCheck) plus the given checks.
func newChainEngine(t *testing.T, extra ...harnessx.Check) *harnessx.Engine {
	t.Helper()
	return newEngine(t, append([]harnessx.Check{
		security.UnkeyedHeaderCheck,
		security.CacheDeceptionCheck,
		security.ErrorCachingCheck,
		security.ResponseSplittingCheck,
		security.CPDoSCheck,
	}, extra...)...)
}

// runChain runs the §5 chain plus extra against srvURL+path and returns the
// named check's result for the "root" resource.
func runChain(t *testing.T, pctx checkbase.ProbeCtx, srvURL, path string, id harnessx.CheckID, extra ...harnessx.Check) harnessx.Result {
	t.Helper()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srvURL + path}}
	summary, err := newChainEngine(t, extra...).Run(context.Background(), harnessx.Target{URL: srvURL, Data: &pctx})
	require.NoError(t, err)
	res, ok := findResult(summary, id, "root")
	require.True(t, ok)
	return res
}

func aggressiveCtx(budget int) checkbase.ProbeCtx {
	return (&checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, MaxAggressiveRequests: budget}).WithDefaults()
}

// fatGETServer is a /search endpoint behind a URL-keyed cache. When
// vulnerable, the origin lets a GET body override the q parameter — the
// discrepancy a cache that ignores bodies can't see.
func fatGETServer(vulnerable bool) *httptest.Server {
	var mu sync.Mutex
	store := map[string]string{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.RequestURI()
		mu.Lock()
		cached, hit := store[key]
		mu.Unlock()
		if hit {
			_, _ = w.Write([]byte(cached))
			return
		}
		term := r.URL.Query().Get("q")
		if vulnerable {
			if b, err := io.ReadAll(r.Body); err == nil && len(b) > 0 {
				term = string(b)
			}
		}
		body := "Results for: " + term
		mu.Lock()
		store[key] = body
		mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))
}

// cloakingServer is a /greet endpoint behind a cache that keys on the query
// string only up to the first ";" while (when vulnerable) the origin reads
// "name" from after one — Rails-style parameter parsing.
func cloakingServer(vulnerable bool) *httptest.Server {
	var mu sync.Mutex
	store := map[string]string{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path + "?" + strings.SplitN(r.URL.RawQuery, ";", 2)[0]
		mu.Lock()
		cached, hit := store[key]
		mu.Unlock()
		if hit {
			_, _ = w.Write([]byte(cached))
			return
		}
		name := "world"
		if vulnerable {
			for _, part := range strings.Split(r.URL.RawQuery, ";") {
				if v, ok := strings.CutPrefix(part, "name="); ok {
					name = v
				}
			}
		}
		body := "Hello, " + name + "!"
		mu.Lock()
		store[key] = body
		mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))
}

func TestEntanglement_GatedOffWithoutAggressive(t *testing.T) {
	srv := fatGETServer(true)
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	res := runChain(t, pctx, srv.URL, "/search?q=cats", checkbase.CheckIDEntanglement, security.EntanglementCheck)
	assert.False(t, res.Skipped)
	assert.Empty(t, res.Observations)
}

func TestEntanglement_DetectsFatGET(t *testing.T) {
	srv := fatGETServer(true)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/search?q=cats", checkbase.CheckIDEntanglement, security.EntanglementCheck)
	require.Len(t, res.Observations, 1)
	assert.Equal(t, "Cache poisoning via fat GET request body", res.Observations[0].Title)
	assert.Equal(t, checkbase.SeverityCritical, res.Observations[0].Metadata[checkbase.SeverityKey])
}

func TestEntanglement_FatGETIgnoredBodyNotFlagged(t *testing.T) {
	srv := fatGETServer(false)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/search?q=cats", checkbase.CheckIDEntanglement, security.EntanglementCheck)
	assert.Empty(t, res.Observations)
}

// TestEntanglement_FatGETDoesNotPoisonCanonicalURL asserts the probe's
// poisoned entry lives on the cache-buster URL only — a real user's plain
// request for the resource never sees the marker.
func TestEntanglement_FatGETDoesNotPoisonCanonicalURL(t *testing.T) {
	srv := fatGETServer(true)
	defer srv.Close()

	runChain(t, aggressiveCtx(10), srv.URL, "/search?q=cats", checkbase.CheckIDEntanglement, security.EntanglementCheck)

	resp, err := http.Get(srv.URL + "/search?q=cats")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(body), "cache-detective-poison-marker.invalid")
}

func TestEntanglement_DetectsParameterCloaking(t *testing.T) {
	srv := cloakingServer(true)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/greet?id=1", checkbase.CheckIDEntanglement, security.EntanglementCheck)
	require.Len(t, res.Observations, 1)
	assert.Equal(t, "Cache poisoning via parameter cloaking (name)", res.Observations[0].Title)
	assert.Contains(t, res.Observations[0].Evidence, ";name=")
}

func TestEntanglement_CloakingIgnoredSemicolonNotFlagged(t *testing.T) {
	srv := cloakingServer(false)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/greet?id=1", checkbase.CheckIDEntanglement, security.EntanglementCheck)
	assert.Empty(t, res.Observations)
}

func TestEntanglement_RespectsRequestBudget(t *testing.T) {
	var mu sync.Mutex
	var probes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only this check sends a GET body or a ";"-cloaked parameter, so
		// counting those isolates its requests from the §5 chain's.
		if r.ContentLength > 0 || strings.Contains(r.URL.RawQuery, ";") {
			mu.Lock()
			probes++
			mu.Unlock()
		}
		_, _ = w.Write([]byte("static"))
	}))
	defer srv.Close()

	runChain(t, aggressiveCtx(4), srv.URL, "/greet?id=1", checkbase.CheckIDEntanglement, security.EntanglementCheck)

	mu.Lock()
	defer mu.Unlock()
	assert.Positive(t, probes)
	assert.LessOrEqual(t, probes, 4)
}
