package checkbase_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

func replayCtx(extra func(*checkbase.ProbeCtx)) *checkbase.ProbeCtx {
	pctx := checkbase.ProbeCtx{
		Resources: []checkbase.ResourceSpec{
			{ID: "/", URL: "https://example.com/", Headers: map[string][]string{"Accept-Language": {"root"}}},
			{
				ID: "/account", URL: "https://example.com/account",
				Headers: map[string][]string{"Accept-Language": {"fr"}, "X-Recorded": {"1"}},
				Cookies: []checkbase.Cookie{{Name: "sid", Value: "recorded"}, {Name: "theme", Value: "dark"}},
			},
			{ID: "/plain", URL: "https://example.com/plain"},
		},
	}
	if extra != nil {
		extra(&pctx)
	}
	out := pctx.WithDefaults()
	return &out
}

func TestNewRequest_ReplaysRecordedCredentials(t *testing.T) {
	pctx := replayCtx(nil)

	for _, u := range []string{
		"https://example.com/account",
		"https://example.com/account?cd_cachebuster=abc", // cache-buster variant
		"https://example.com/account/x.css",              // path-confusion variant
	} {
		req, err := checkbase.NewRequest(context.Background(), u, pctx, nil)
		require.NoError(t, err)
		assert.Equal(t, "fr", req.Header.Get("Accept-Language"), u)
		assert.Equal(t, "1", req.Header.Get("X-Recorded"), u)
		assert.Equal(t, "sid=recorded; theme=dark", req.Header.Get("Cookie"), u)
		assert.True(t, checkbase.IsAuthenticated(u, pctx), u)
	}

	// Longest-prefix match: /account wins over "/" for a nested path, and a
	// resource with nothing recorded gets the root's headers but no cookies.
	req, _ := checkbase.NewRequest(context.Background(), "https://example.com/plain", pctx, nil)
	assert.Equal(t, "root", req.Header.Get("Accept-Language"))
	assert.Empty(t, req.Header.Get("Cookie"))
	assert.False(t, checkbase.IsAuthenticated("https://example.com/plain", pctx))

	// Other origins never receive recorded credentials.
	req, _ = checkbase.NewRequest(context.Background(), "https://other.example.net/account", pctx, nil)
	assert.Empty(t, req.Header.Get("Cookie"))
	assert.Empty(t, req.Header.Get("X-Recorded"))
}

func TestNewRequest_ExplicitSettingsOverrideRecorded(t *testing.T) {
	pctx := replayCtx(func(p *checkbase.ProbeCtx) {
		p.Headers = map[string][]string{"accept-language": {"de"}}
		p.Cookies = []checkbase.Cookie{{Name: "sid", Value: "explicit"}}
	})

	req, err := checkbase.NewRequest(context.Background(), "https://example.com/account", pctx, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"de"}, req.Header.Values("Accept-Language"))
	assert.Equal(t, "theme=dark; sid=explicit", req.Header.Get("Cookie"))
	assert.Equal(t, "1", req.Header.Get("X-Recorded"))

	cookies := checkbase.EffectiveCookies("https://example.com/account", pctx)
	require.Len(t, cookies, 2)
}

func TestNewRequest_RecordedAuthorizationHeaderIsAuthenticated(t *testing.T) {
	pctx := replayCtx(func(p *checkbase.ProbeCtx) {
		p.Resources = []checkbase.ResourceSpec{{URL: "https://api.example.com/me", Headers: map[string][]string{"Authorization": {"Bearer t"}}}}
	})
	req, err := checkbase.NewRequest(context.Background(), "https://api.example.com/me", pctx, nil)
	require.NoError(t, err)
	assert.Equal(t, "Bearer t", req.Header.Get("Authorization"))
	assert.True(t, checkbase.IsAuthenticated("https://api.example.com/me", pctx))
}

func TestNewRequest_NoReplayWithoutWithDefaults(t *testing.T) {
	pctx := &checkbase.ProbeCtx{Resources: []checkbase.ResourceSpec{{URL: "https://example.com/", Cookies: []checkbase.Cookie{{Name: "a", Value: "b"}}}}}
	req, err := checkbase.NewRequest(context.Background(), "https://example.com/", pctx, nil)
	require.NoError(t, err)
	assert.Empty(t, req.Header.Get("Cookie"))
}
