package cache_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
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

func TestChecks_TaggedPassiveOrAggressive(t *testing.T) {
	for _, c := range cache.Checks() {
		if c.Internal {
			continue
		}
		passive, aggressive := slices.Contains(c.Tags, cache.TagPassive), slices.Contains(c.Tags, cache.TagAggressive)
		assert.NotEqual(t, passive, aggressive, "exactly one of passive/aggressive: %s %v", c.ID, c.Tags)
	}
	byID := map[harnessx.CheckID]harnessx.Check{}
	for _, c := range cache.Checks() {
		byID[c.ID] = c
	}
	assert.Contains(t, byID[checkbase.CheckIDAuthCacheable].Tags, cache.TagPassive)
	assert.Contains(t, byID[checkbase.CheckIDCacheDeception].Tags, cache.TagAggressive)
	assert.Contains(t, byID[checkbase.CheckIDUnkeyedHeader].Tags, cache.TagAggressive)
}

func TestResolveCheckID_LegacyAliases(t *testing.T) {
	for legacy, want := range map[string]harnessx.CheckID{
		"authenticated-cacheable":  checkbase.CheckIDAuthCacheable,
		"cache-deception":          checkbase.CheckIDCacheDeception,
		"unkeyed-header-injection": checkbase.CheckIDUnkeyedHeader,
		"live-state":               checkbase.CheckIDLiveState,
		"cache.consistency":        checkbase.CheckIDConsistency,
	} {
		got, ok := cache.ResolveCheckID(legacy)
		assert.True(t, ok, legacy)
		assert.Equal(t, want, got, legacy)
	}
	_, ok := cache.ResolveCheckID("nope")
	assert.False(t, ok)

	// Every pre-pack ID selects the check it always did.
	pack := cache.Checks()
	for _, legacy := range []string{"cacheability", "vary-key", "cpdos", "cache-entanglement", "session-cacheable", "stale-serving"} {
		id, ok := cache.ResolveCheckID(legacy)
		require.True(t, ok, legacy)
		_, err := embed.Select(pack, id)
		assert.NoError(t, err, legacy)
	}
}

// A host engine that supplies its own resources — a POST with headers and a
// body — and holds another pack alongside this one.
func TestChecks_EmbedOnHostResources(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{} // path -> "METHOD|X-Op|body"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen[r.URL.Path] = r.Method + "|" + r.Header.Get("X-Op") + "|" + string(body) + "|" + r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Cache-Control", "max-age=600")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pack, err := embed.Select(cache.Checks(), checkbase.CheckIDAuthCacheable)
	require.NoError(t, err)
	checks, err := embed.Checks(pack, embed.Options{
		Scope:     harnessx.ScopePerResource,
		Prefix:    "proxy.",
		DependsOn: []harnessx.CheckID{"host.resources"},
		Context: func(context.Context, harnessx.Target, *harnessx.Resource) (any, error) {
			return cache.NewProbeCtx(checkbase.ProbeCtx{Probe: probe.New(), Headers: map[string][]string{"X-Op": {"scan-wide"}}}), nil
		},
	})
	require.NoError(t, err)

	other := harnessx.Check{
		ID:    "other.pack_check",
		Name:  "Another pack",
		Scope: harnessx.ScopeGlobal,
		Run: func(context.Context, harnessx.Target, harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{}, nil
		},
	}
	hostResources := harnessx.Check{
		ID:       "host.resources",
		Name:     "Host resources",
		Internal: true,
		Scope:    harnessx.ScopeGlobal,
		Run: func(context.Context, harnessx.Target, harnessx.ResultStore) (harnessx.Result, error) {
			return harnessx.Result{Resources: []harnessx.Resource{
				{ID: "create", URL: srv.URL + "/create", Method: http.MethodPost, Data: checkbase.ResourceRequest{
					Headers: map[string][]string{"x-op": {"create"}, "Authorization": {"Bearer op-token"}},
					Body:    []byte(`{"a":1}`),
				}},
				{ID: "list", URL: srv.URL + "/list", Method: http.MethodGet},
			}}, nil
		},
	}
	engine := harnessx.New()
	require.NoError(t, engine.Register(append([]harnessx.Check{hostResources, other}, checks...)...))
	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL})
	require.NoError(t, err)

	for _, r := range summary.Results {
		assert.NoError(t, r.Err, "%s", r.CheckID)
	}
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, `POST|create|{"a":1}|Bearer op-token`, seen["/create"])
	assert.Equal(t, "GET|scan-wide||", seen["/list"])

	flagged := map[string]bool{}
	for _, o := range summary.Observations {
		if o.CheckID == "proxy.cache.authenticated_cacheable" {
			flagged[o.ResourceID] = true
		}
	}
	assert.True(t, flagged["create"], "the resource's own Authorization makes it authenticated: %+v", summary.Observations)
	assert.False(t, flagged["list"])
}
