package checkbase_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

func TestNewRequest_GlobalAuthDefaults(t *testing.T) {
	pctx := &checkbase.ProbeCtx{
		Headers:     map[string][]string{"X-App": {"cache-detective"}},
		Cookies:     []checkbase.Cookie{{Name: "session", Value: "global"}},
		BearerToken: "global-token",
	}

	req, err := checkbase.NewRequest(context.Background(), "https://example.com/resource", pctx, nil)
	require.NoError(t, err)

	assert.Equal(t, "cache-detective", req.Header.Get("X-App"))
	assert.Equal(t, "Bearer global-token", req.Header.Get("Authorization"))
	cookie, err := req.Cookie("session")
	require.NoError(t, err)
	assert.Equal(t, "global", cookie.Value)
}

func TestNewRequest_AuthProfileOverridesByOrigin(t *testing.T) {
	pctx := &checkbase.ProbeCtx{
		BearerToken: "global-token",
		AuthProfiles: map[string]checkbase.AuthProfile{
			"https://api.example.com": {
				BearerToken: "api-token",
				Headers:     map[string][]string{"X-API-Key": {"secret"}},
			},
		},
	}

	apiReq, err := checkbase.NewRequest(context.Background(), "https://api.example.com/resource", pctx, nil)
	require.NoError(t, err)
	assert.Equal(t, "Bearer api-token", apiReq.Header.Get("Authorization"))
	assert.Equal(t, "secret", apiReq.Header.Get("X-API-Key"))

	otherReq, err := checkbase.NewRequest(context.Background(), "https://other.example.com/resource", pctx, nil)
	require.NoError(t, err)
	assert.Equal(t, "Bearer global-token", otherReq.Header.Get("Authorization"))
	assert.Empty(t, otherReq.Header.Get("X-API-Key"))
}

func TestLoadAuthProfiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth-profiles.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
		"https://api.example.com": {
			"bearer": "api-token",
			"headers": {"X-API-Key": ["secret"]},
			"cookies": {"session": "abc123"}
		}
	}`), 0o600))

	profiles, err := checkbase.LoadAuthProfiles(path)
	require.NoError(t, err)
	require.Contains(t, profiles, "https://api.example.com")

	profile := profiles["https://api.example.com"]
	assert.Equal(t, "api-token", profile.BearerToken)
	assert.Equal(t, []string{"secret"}, profile.Headers["X-API-Key"])
	require.Len(t, profile.Cookies, 1)
	assert.Equal(t, "session", profile.Cookies[0].Name)
	assert.Equal(t, "abc123", profile.Cookies[0].Value)
}

func TestLoadAuthProfiles_MissingFile(t *testing.T) {
	_, err := checkbase.LoadAuthProfiles(filepath.Join(t.TempDir(), "missing.json"))
	assert.Error(t, err)
}
