package cache_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cache "github.com/cerberauth/cache-detective/cache"
	"github.com/cerberauth/cache-detective/cache/checkbase"
)

func TestScanAll_NonAggressive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Server", "Fastly")
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pctx := checkbase.ProbeCtx{
		Probe:     probe.New(),
		Resources: []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}},
	}

	summary, err := cache.ScanAll(context.Background(), srv.URL, cache.ScanOptions{
		ProbeCtx:   pctx,
		RunOptions: []harnessx.RunOption{harnessx.WithMaxCVSSScore(0)}, // exclude the aggressive-only security checks
	})
	require.NoError(t, err)
	assert.Equal(t, 0, summary.Failed)
	assert.NotZero(t, summary.Executed)
}

func TestScanAll_Aggressive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pctx := checkbase.ProbeCtx{
		Probe:                 probe.New(),
		Aggressive:            true,
		MaxAggressiveRequests: 5,
		Resources:             []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}},
	}

	summary, err := cache.ScanAll(context.Background(), srv.URL, cache.ScanOptions{ProbeCtx: pctx})
	require.NoError(t, err)
	assert.Equal(t, 0, summary.Failed)
}

// TestBuildChecks_EveryCheckHasADef guards the two parallel lists in
// BuildChecks: a check registered without a CheckDef (or a Def with no check)
// would drop out of reports' CVSS/CWE enrichment without any other test
// noticing.
func TestBuildChecks_EveryCheckHasADef(t *testing.T) {
	checks, defs := cache.BuildChecks()

	registered := map[harnessx.CheckID]bool{}
	for _, c := range checks {
		registered[c.ID] = true
		if c.ID == checkbase.CheckIDDiscovery {
			continue // global seeding check, not a reportable one
		}
		assert.Contains(t, defs, c.ID, "check %q has no CheckDef", c.ID)
	}
	for id := range defs {
		assert.True(t, registered[id], "CheckDef %q has no registered check", id)
	}
}
