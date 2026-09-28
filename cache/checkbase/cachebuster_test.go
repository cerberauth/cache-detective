package checkbase_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

func TestNewCacheBusterProbe_QueryModeDefault(t *testing.T) {
	pctx := (&checkbase.ProbeCtx{}).WithDefaults()

	probe, err := checkbase.NewCacheBusterProbe("https://example.com/resource?a=1", &pctx)
	require.NoError(t, err)

	u, err := url.Parse(probe.URL)
	require.NoError(t, err)
	assert.Equal(t, "1", u.Query().Get("a"), "existing query params must survive")
	token := u.Query().Get("cd_cachebuster")
	assert.NotEmpty(t, token, "default query param name must carry a token")
	assert.Nil(t, probe.Header, "query mode must not add a header")
}

func TestNewCacheBusterProbe_HeaderMode(t *testing.T) {
	pctx := (&checkbase.ProbeCtx{CacheBuster: checkbase.CacheBusterConfig{Mode: checkbase.CacheBusterHeader}}).WithDefaults()

	probe, err := checkbase.NewCacheBusterProbe("https://example.com/resource", &pctx)
	require.NoError(t, err)

	assert.Equal(t, "https://example.com/resource", probe.URL, "header mode must leave the URL untouched")
	require.NotNil(t, probe.Header)
	assert.NotEmpty(t, probe.Header.Get("X-Cache-Detective-Buster"))
}

func TestNewCacheBusterProbe_BothModeAndCustomNames(t *testing.T) {
	pctx := (&checkbase.ProbeCtx{CacheBuster: checkbase.CacheBusterConfig{
		Mode:       checkbase.CacheBusterBoth,
		QueryParam: "cb",
		HeaderName: "X-Buster",
	}}).WithDefaults()

	probe, err := checkbase.NewCacheBusterProbe("https://example.com/resource", &pctx)
	require.NoError(t, err)

	u, err := url.Parse(probe.URL)
	require.NoError(t, err)
	require.NotEmpty(t, u.Query().Get("cb"))
	require.NotNil(t, probe.Header)
	assert.NotEmpty(t, probe.Header.Get("X-Buster"))
}

func TestNewCacheBusterProbe_TokensAreUniquePerCall(t *testing.T) {
	pctx := (&checkbase.ProbeCtx{}).WithDefaults()

	first, err := checkbase.NewCacheBusterProbe("https://example.com/resource", &pctx)
	require.NoError(t, err)
	second, err := checkbase.NewCacheBusterProbe("https://example.com/resource", &pctx)
	require.NoError(t, err)

	assert.NotEqual(t, first.URL, second.URL, "each attempt must get its own isolated cache entry")
}

func TestMergeHeader(t *testing.T) {
	a := http.Header{"X-A": {"1"}}
	b := http.Header{"X-B": {"2"}}

	merged := checkbase.MergeHeader(a, b)
	assert.Equal(t, "1", merged.Get("X-A"))
	assert.Equal(t, "2", merged.Get("X-B"))

	assert.Equal(t, b, checkbase.MergeHeader(nil, b))
	assert.Equal(t, a, checkbase.MergeHeader(a, nil))
}
