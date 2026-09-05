package varykey_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/varykey"
)

func TestCheck_UndeclaredUserAgentKeying(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Vary header declared, but the body reflects User-Agent —
		// an undeclared cache-key input.
		w.Write([]byte("ua=" + r.Header.Get("User-Agent")))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := harnessx.New()
	require.NoError(t, engine.Register(checkbase.DiscoveryCheck, varykey.Check))

	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)
	assert.Equal(t, 0, summary.Failed)

	res, ok := findResult(summary, checkbase.CheckIDVaryKey, "root")
	require.True(t, ok)
	data, ok := harnessx.DataAs[varykey.Result](res)
	require.True(t, ok)

	var found bool
	for _, p := range data.Probes {
		if p.Dimension == "user-agent" {
			found = true
			assert.True(t, p.Keyed)
			assert.False(t, p.Declared)
		}
	}
	assert.True(t, found)
	assert.NotEmpty(t, res.Observations)
}

func TestCheck_DeclaredVaryWithNoEffect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Accept-Encoding")
		w.Write([]byte("static"))
	}))
	defer srv.Close()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := harnessx.New()
	require.NoError(t, engine.Register(checkbase.DiscoveryCheck, varykey.Check))

	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)

	res, ok := findResult(summary, checkbase.CheckIDVaryKey, "root")
	require.True(t, ok)
	var found bool
	for _, o := range res.Observations {
		if o.Title == "Declared Vary dimension has no observed effect: accept-encoding" {
			found = true
		}
	}
	assert.True(t, found)
}

func findResult(summary harnessx.ScanSummary, id harnessx.CheckID, resourceID string) (harnessx.Result, bool) {
	for _, r := range summary.Results {
		if r.CheckID == id && r.ResourceID == resourceID {
			return r, true
		}
	}
	return harnessx.Result{}, false
}
