package cache_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/embed"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cache "github.com/cerberauth/cache-detective/cache"
	"github.com/cerberauth/cache-detective/cache/checkbase"
)

var packID = regexp.MustCompile(`^cache\.[a-z0-9]+(_[a-z0-9]+)*$`)

func TestChecks_FollowPackContract(t *testing.T) {
	checks := cache.Checks()
	require.NotEmpty(t, checks)
	for _, c := range checks {
		assert.Regexp(t, packID, string(c.ID))
		assert.Equal(t, c.ID == checkbase.CheckIDDiscovery, c.Internal, "only discovery is internal: %s", c.ID)
	}
	require.NoError(t, harnessx.New().Register(checks...))
}

func TestNewRequestFactory(t *testing.T) {
	pctx := cache.NewProbeCtx(checkbase.ProbeCtx{
		BearerToken: "tok",
		NewRequest: func(ctx context.Context, _ string, url string) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("{}"))
		},
	})
	req, err := checkbase.NewRequest(context.Background(), "http://example.test/a", pctx, http.Header{"X-Probe": {"1"}})
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "Bearer tok", req.Header.Get("Authorization"))
	assert.Equal(t, "1", req.Header.Get("X-Probe"))
}

func TestChecks_EmbedOnSingleTarget(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=600")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pack, err := embed.Select(cache.Checks(), checkbase.CheckIDAuthCacheable)
	require.NoError(t, err)
	checks, err := embed.Checks(pack, embed.Options{
		Scope:  harnessx.ScopeGlobal,
		Prefix: "proxy.",
		Context: func(context.Context, harnessx.Target, *harnessx.Resource) (any, error) {
			return cache.NewProbeCtx(checkbase.ProbeCtx{Probe: probe.New(), BearerToken: "tok"}), nil
		},
	})
	require.NoError(t, err)

	summary, err := harnessx.New(harnessx.WithChecks(checks...)).Run(context.Background(), harnessx.Target{URL: srv.URL})
	require.NoError(t, err)

	ran := map[harnessx.CheckID]bool{}
	for _, r := range summary.Results {
		assert.NoError(t, r.Err, "%s", r.CheckID)
		assert.True(t, strings.HasPrefix(string(r.CheckID), "proxy.cache."), "%s", r.CheckID)
		ran[r.CheckID] = !r.Skipped
	}
	assert.True(t, ran["proxy.cache.cacheability"])
	assert.True(t, ran["proxy.cache.authenticated_cacheable"])

	var found bool
	for _, o := range summary.Observations {
		found = found || o.CheckID == "proxy.cache.authenticated_cacheable"
	}
	assert.True(t, found, "observations: %+v", summary.Observations)
}
