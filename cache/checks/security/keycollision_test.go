package security_test

import (
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/security"
)

// keyCollisionServer is an origin that routes the raw request path (anything
// under /static/ is static content, /account is private data, else 404) behind
// a cache that keys on the path with "../" resolved when cacheNormalizes.
func keyCollisionServer(cacheNormalizes bool) *httptest.Server {
	var mu sync.Mutex
	store := map[string]string{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Path
		key := raw
		if cacheNormalizes {
			key = path.Clean(raw)
		}
		mu.Lock()
		cached, hit := store[key]
		mu.Unlock()
		if hit {
			_, _ = w.Write([]byte(cached))
			return
		}
		var body string
		switch {
		case strings.HasPrefix(raw, "/static/"):
			body = "static bundle for " + raw
		case raw == "/account":
			body = "account data"
		default:
			w.WriteHeader(http.StatusNotFound)
			body = "not found"
		}
		mu.Lock()
		store[key] = body
		mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))
}

func TestKeyCollision_GatedOffWithoutAggressive(t *testing.T) {
	srv := keyCollisionServer(true)
	defer srv.Close()

	pctx := aggressiveCtx(10)
	pctx.Aggressive = false
	res := runChain(t, pctx, srv.URL, "/account", checkbase.CheckIDKeyCollision, security.KeyCollisionCheck)
	assert.False(t, res.Skipped)
	assert.Empty(t, res.Observations)
}

func TestKeyCollision_DetectsNormalizingCache(t *testing.T) {
	srv := keyCollisionServer(true)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/account", checkbase.CheckIDKeyCollision, security.KeyCollisionCheck)
	require.Len(t, res.Observations, 1)
	assert.Equal(t, "Cache-key path collision via path traversal", res.Observations[0].Title)
	assert.Equal(t, checkbase.SeverityCritical, res.Observations[0].Metadata[checkbase.SeverityKey])
	assert.Contains(t, res.Observations[0].Evidence, "/static/")
}

func TestKeyCollision_NeverTouchesTheResourceItself(t *testing.T) {
	srv := keyCollisionServer(true)
	defer srv.Close()

	runChain(t, aggressiveCtx(10), srv.URL, "/account", checkbase.CheckIDKeyCollision, security.KeyCollisionCheck)

	// The collided-onto path is a random one, so a real user's /account is
	// still the origin's own response.
	resp, err := http.Get(srv.URL + "/account")
	require.NoError(t, err)
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	assert.Equal(t, "account data", string(buf[:n]))
}

func TestKeyCollision_CacheKeyingRawPathNotFlagged(t *testing.T) {
	srv := keyCollisionServer(false)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/account", checkbase.CheckIDKeyCollision, security.KeyCollisionCheck)
	assert.Empty(t, res.Observations)
}

// TestKeyCollision_NormalizingOriginNotFlagged: when the origin itself
// resolves "../" there is no cache/origin discrepancy, whatever the cache does.
func TestKeyCollision_NormalizingOriginNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(path.Clean(r.URL.Path), "/static/") {
			_, _ = w.Write([]byte("static bundle"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/account", checkbase.CheckIDKeyCollision, security.KeyCollisionCheck)
	assert.Empty(t, res.Observations)
}

func TestKeyCollision_CatchAllOriginNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("single page app"))
	}))
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/account", checkbase.CheckIDKeyCollision, security.KeyCollisionCheck)
	assert.Empty(t, res.Observations)
}
