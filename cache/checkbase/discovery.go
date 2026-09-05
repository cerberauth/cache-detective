package checkbase

import (
	"context"

	"github.com/cerberauth/harnessx"
)

// DiscoveryCheck is the ScopeGlobal check every per-resource check depends
// on. It does no network I/O of its own — resolving the resource list (a
// single URL, a list file, a sitemap, a .har import, or a crawl) happens
// ahead of the scan in the CLI layer / cache/crawl package; DiscoveryCheck
// just publishes ProbeCtx.Resources into the harnessx resource pool.
var DiscoveryCheck = harnessx.Check{
	ID:    CheckIDDiscovery,
	Name:  "Resource Discovery",
	Scope: harnessx.ScopeGlobal,
	Run: func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
		pctx := target.Data.(*ProbeCtx)
		resources := make([]harnessx.Resource, 0, len(pctx.Resources))
		for _, r := range pctx.Resources {
			method := r.Method
			if method == "" {
				method = pctx.Method
			}
			resources = append(resources, harnessx.Resource{ID: r.ID, URL: r.URL, Method: method})
		}
		return harnessx.Result{Resources: resources}, nil
	},
}
