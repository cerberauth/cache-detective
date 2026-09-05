package fingerprint_test

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
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
	"github.com/cerberauth/cache-detective/cache/checks/fingerprint"
	"github.com/cerberauth/cache-detective/cache/checks/livestate"
)

type fakeResolver struct {
	chain []string
}

func (f fakeResolver) LookupCNAME(context.Context, string) ([]string, error) {
	return f.chain, nil
}

func TestCheck_CNAMEFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	orig := fingerprint.Resolver
	fingerprint.Resolver = fakeResolver{chain: []string{"d123.cloudfront.net."}}
	defer func() { fingerprint.Resolver = orig }()

	pctx := (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srv.URL}}

	engine := harnessx.New()
	require.NoError(t, engine.Register(checkbase.DiscoveryCheck, cacheability.Check, livestate.Check, fingerprint.Check))

	summary, err := engine.Run(context.Background(), harnessx.Target{URL: srv.URL, Data: &pctx})
	require.NoError(t, err)
	assert.Equal(t, 0, summary.Failed)

	res, ok := findResult(summary, checkbase.CheckIDFingerprint, "root")
	require.True(t, ok)
	fp, ok := harnessx.DataAs[fingerprint.Result](res)
	require.True(t, ok)
	assert.Equal(t, "Amazon CloudFront", fp.CDN)
	assert.Equal(t, "cname", fp.Source)
}

func findResult(summary harnessx.ScanSummary, id harnessx.CheckID, resourceID string) (harnessx.Result, bool) {
	for _, r := range summary.Results {
		if r.CheckID == id && r.ResourceID == resourceID {
			return r, true
		}
	}
	return harnessx.Result{}, false
}
