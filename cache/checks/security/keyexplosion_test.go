package security_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/security"
)

var tokenRe = regexp.MustCompile(`^cd[0-9a-f]{16}$`)

// keyExplosionServer keys its cache on the q value. cap > 0 sends every
// value beyond the first cap distinct ones to one shared overflow entry;
// reportStatus controls whether X-Cache is emitted at all.
func keyExplosionServer(cap int, reportStatus bool) *httptest.Server {
	var mu sync.Mutex
	store := map[string]bool{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("q")
		mu.Lock()
		if cap > 0 && !store[key] && len(store) >= cap {
			key = "__overflow__"
		}
		hit := store[key]
		store[key] = true
		mu.Unlock()

		if reportStatus {
			if hit {
				w.Header().Set("X-Cache", "HIT")
			} else {
				w.Header().Set("X-Cache", "MISS")
			}
		}
		_, _ = w.Write([]byte("results"))
	}))
}

func TestKeyExplosion_GatedOffWithoutAggressive(t *testing.T) {
	srv := keyExplosionServer(0, true)
	defer srv.Close()

	pctx := aggressiveCtx(30)
	pctx.Aggressive = false
	res := runChain(t, pctx, srv.URL, "/search?q=test", checkbase.CheckIDKeyExplosion, security.KeyExplosionCheck)
	assert.False(t, res.Skipped)
	assert.Empty(t, res.Observations)
}

func TestKeyExplosion_DetectsUnboundedKeys(t *testing.T) {
	srv := keyExplosionServer(0, true)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(30), srv.URL, "/search?q=test", checkbase.CheckIDKeyExplosion, security.KeyExplosionCheck)
	require.Len(t, res.Observations, 1)
	assert.Equal(t, "Unbounded cache-key cardinality", res.Observations[0].Title)
	assert.Equal(t, checkbase.SeverityLow, res.Observations[0].Metadata[checkbase.SeverityKey])
	assert.Contains(t, res.Observations[0].Description, `"q"`)
}

func TestKeyExplosion_CappedCacheNotFlagged(t *testing.T) {
	srv := keyExplosionServer(16, true)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(30), srv.URL, "/search?q=test", checkbase.CheckIDKeyExplosion, security.KeyExplosionCheck)
	assert.Empty(t, res.Observations)
}

func TestKeyExplosion_NoCacheStatusHeaderNotFlagged(t *testing.T) {
	srv := keyExplosionServer(0, false)
	defer srv.Close()

	res := runChain(t, aggressiveCtx(30), srv.URL, "/search?q=test", checkbase.CheckIDKeyExplosion, security.KeyExplosionCheck)
	assert.Empty(t, res.Observations)
}

// TestKeyExplosion_BelowMinimumBudgetSendsNothing: with fewer requests than
// the sample needs there's no way to tell "no cap" from "a cap above the
// sample", so the check stays out of the way instead of guessing.
func TestKeyExplosion_BelowMinimumBudgetSendsNothing(t *testing.T) {
	var probes int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only this check varies q with a random "cd<16 hex>" token.
		if tokenRe.MatchString(r.URL.Query().Get("q")) {
			atomic.AddInt64(&probes, 1)
		}
		w.Header().Set("X-Cache", "MISS")
		_, _ = w.Write([]byte("results"))
	}))
	defer srv.Close()

	res := runChain(t, aggressiveCtx(10), srv.URL, "/search?q=test", checkbase.CheckIDKeyExplosion, security.KeyExplosionCheck)
	assert.Empty(t, res.Observations)
	assert.Zero(t, atomic.LoadInt64(&probes))
}
