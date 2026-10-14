package security_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/security"
)

// staticDirServer serves /account (secret) and, when originNormalizes, also
// for any traversal path that resolves to it. Requests whose raw path starts
// under /static/ are "cached" by a path-keyed cache that reports
// X-Cache MISS then HIT, if cacheReports is set.
func staticDirServer(originNormalizes, cacheReports bool) *httptest.Server {
	var mu sync.Mutex
	seen := map[string]bool{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Path
		resolved := raw
		if originNormalizes {
			resolved = path.Clean(raw)
		}
		if resolved != "/account" {
			http.NotFound(w, r)
			return
		}
		if cacheReports && strings.HasPrefix(raw, "/static/") {
			mu.Lock()
			hit := seen[raw]
			seen[raw] = true
			mu.Unlock()
			if hit {
				w.Header().Set("X-Cache", "HIT")
			} else {
				w.Header().Set("X-Cache", "MISS")
			}
		}
		_, _ = w.Write([]byte("secret-account-data"))
	}))
}

func TestNormalizationDeception_GatedOffWithoutAggressive(t *testing.T) {
	srv := staticDirServer(true, true)
	defer srv.Close()

	pctx := aggressiveCtx(10)
	pctx.Aggressive = false
	res := runChain(t, pctx, srv.URL, "/account", checkbase.CheckIDNormalizationDeception, security.NormalizationDeceptionCheck)
	assert.False(t, res.Skipped)
	assert.Empty(t, res.Observations)
}

func TestNormalizationDeception_DetectsStaticDirectoryTraversal(t *testing.T) {
	srv := staticDirServer(true, true)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/account", checkbase.CheckIDNormalizationDeception, security.NormalizationDeceptionCheck)
	titles := observationTitles(res.Observations)
	assert.Contains(t, titles, "Cache deception via static-directory path traversal")
	for _, o := range res.Observations {
		assert.Equal(t, checkbase.SeverityHigh, o.Metadata[checkbase.SeverityKey], "a repeat-request HIT confirms caching: %s", o.Title)
		assert.Contains(t, o.Evidence, "/static/")
	}
}

func TestNormalizationDeception_UnconfirmedCachingIsMedium(t *testing.T) {
	srv := staticDirServer(true, false) // no cache-status header to observe
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/account", checkbase.CheckIDNormalizationDeception, security.NormalizationDeceptionCheck)
	require.NotEmpty(t, res.Observations)
	for _, o := range res.Observations {
		assert.Equal(t, checkbase.SeverityMedium, o.Metadata[checkbase.SeverityKey])
	}
}

func TestNormalizationDeception_OriginWithoutNormalizationNotFlagged(t *testing.T) {
	srv := staticDirServer(false, true)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/account", checkbase.CheckIDNormalizationDeception, security.NormalizationDeceptionCheck)
	assert.Empty(t, res.Observations)
}

// TestNormalizationDeception_LooseRoutingNotAttributed: an origin that
// answers /account for anything ending in it would match every variant for
// reasons unrelated to path normalization; the no-traversal control request
// catches it.
func TestNormalizationDeception_LooseRoutingNotAttributed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret-account-data"))
	}))
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/account", checkbase.CheckIDNormalizationDeception, security.NormalizationDeceptionCheck)
	assert.Empty(t, res.Observations)
}

func TestNormalizationDeception_AlreadyCachedResourceNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if path.Clean(r.URL.Path) != "/account" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Cache", "HIT")
		_, _ = w.Write([]byte("public-content"))
	}))
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/account", checkbase.CheckIDNormalizationDeception, security.NormalizationDeceptionCheck)
	assert.Empty(t, res.Observations)
}

func TestNormalizationDeception_DetectsNestedEncodedTraversal(t *testing.T) {
	// The origin decodes repeatedly (a double-encoded separator becomes a
	// real one) before normalizing; the cache decodes once and sees /static/.
	var mu sync.Mutex
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.RequestURI
		decoded := raw
		for {
			next, err := pathUnescape(decoded)
			if err != nil || next == decoded {
				break
			}
			decoded = next
		}
		if path.Clean(decoded) != "/account" {
			http.NotFound(w, r)
			return
		}
		if once, _ := pathUnescape(raw); strings.HasPrefix(once, "/static/") {
			mu.Lock()
			hit := seen[raw]
			seen[raw] = true
			mu.Unlock()
			if hit {
				w.Header().Set("X-Cache", "HIT")
			} else {
				w.Header().Set("X-Cache", "MISS")
			}
		}
		_, _ = w.Write([]byte("secret-account-data"))
	}))
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/account", checkbase.CheckIDNormalizationDeception, security.NormalizationDeceptionCheck)
	assert.Contains(t, observationTitles(res.Observations), "Cache deception via nested-encoded static-directory path traversal")
}

func pathUnescape(s string) (string, error) { return url.PathUnescape(s) }
