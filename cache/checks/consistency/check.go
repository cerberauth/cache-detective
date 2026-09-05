// Package consistency implements §6 of cache-detective: response
// consistency & correctness — conditional-request handling
// (If-None-Match/If-Modified-Since should yield 304), redirect caching
// behavior, and stale-beyond-TTL detection.
package consistency

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
)

// Def describes the response-consistency check.
var Def = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDConsistency),
	Name:        "Response Consistency & Correctness",
	Description: "Validates conditional-request handling (If-None-Match/If-Modified-Since expected to return 304) and redirect caching behavior.",
	Tags:        []string{"consistency", "validation"},
	DependsOn:   []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDCacheability)},
}

// Check runs response-consistency validation against each resource.
var Check = checkdef.NewResourceCheck(Def, run)

// Result is the consistency-check outcome for one resource.
type Result struct {
	ConditionalRequestHonored *bool // nil when no validator was available to test with
	IsRedirect                bool
	RedirectCacheable         bool
}

func run(ctx context.Context, target harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	pctx := target.Data.(*checkbase.ProbeCtx)

	baseReq, err := checkbase.NewRequest(ctx, resource.URL, pctx, nil)
	if err != nil {
		return harnessx.Result{}, err
	}
	base, err := checkbase.Do(ctx, pctx, baseReq)
	if err != nil {
		return harnessx.Result{}, err
	}

	res := Result{}
	var obs []harnessx.Observation

	if isRedirectStatus(base.StatusCode) {
		res.IsRedirect = true
		dep, ok := store.GetForResource(checkbase.CheckIDCacheability, resource.ID)
		if ok && !dep.Skipped {
			if analysis, ok := harnessx.DataAs[cacheability.AnalysisResult](dep); ok {
				res.RedirectCacheable = analysis.Cacheable
				if analysis.Cacheable && analysis.CacheControl.MaxAge == nil && analysis.CacheControl.SMaxAge == nil && analysis.Expires == nil {
					obs = append(obs, harnessx.Observation{
						Title:       "Redirect cached with only heuristic freshness",
						Description: fmt.Sprintf("a %d redirect is cacheable by default status semantics but carries no explicit freshness (max-age/s-maxage/Expires) — caches may apply their own heuristic TTL, which can outlive the redirect's intended lifetime", base.StatusCode),
						Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityLow},
					})
				}
			}
		}
	}

	etag := base.Header.Get("ETag")
	lastMod := base.Header.Get("Last-Modified")
	if etag != "" || lastMod != "" {
		condHeader := http.Header{}
		if etag != "" {
			condHeader.Set("If-None-Match", etag)
		}
		if lastMod != "" {
			condHeader.Set("If-Modified-Since", lastMod)
		}
		condReq, err := checkbase.NewRequest(ctx, resource.URL, pctx, condHeader)
		if err == nil {
			cond, err := checkbase.Do(ctx, pctx, condReq)
			if err == nil {
				honored := cond.StatusCode == http.StatusNotModified
				res.ConditionalRequestHonored = &honored
				if !honored {
					obs = append(obs, harnessx.Observation{
						Title:       "Conditional request not honored",
						Description: fmt.Sprintf("a request with If-None-Match/If-Modified-Since matching the resource's own validator got status %d instead of 304 Not Modified — the origin/cache isn't revalidating correctly, forcing full re-transfers", cond.StatusCode),
						Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityLow},
					})
				}
			}
		}
	}

	for i := range obs {
		obs[i].CheckID = checkbase.CheckIDConsistency
		obs[i].ResourceID = resource.ID
	}
	return harnessx.Result{Data: res, Observations: obs}, nil
}

func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// StaleBeyondTTL reports whether a resource served from cache is stale
// beyond its declared freshness lifetime, given the response's Age and the
// freshness lifetime computed from Cache-Control/Expires. It's exported as
// a standalone function (rather than folded into run) so the live-state
// check's multi-sample data can reuse it without another request.
func StaleBeyondTTL(age time.Duration, freshnessLifetime time.Duration) bool {
	return freshnessLifetime > 0 && age > freshnessLifetime
}
