package staleserving

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
)

// simulateErrorHeader is the probe header stale-if-error confirmation sends
// to try to make the origin fail. It only has an effect against
// origins/test fixtures that explicitly honor it (see testdata/fixtureserver)
// — real, uninstrumented origins simply ignore it, which the check treats
// as an inconclusive (not a negative) result. Aggressive-gated because it's
// asking the origin to misbehave, the same posture as the §5 security
// checks.
const simulateErrorHeader = "X-Cache-Detective-Simulate-Error"

// Def describes the stale-serving behavior check.
var Def = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDStaleServing),
	Name:        "Stale-Serving Behavior (RFC 5861)",
	Description: "Confirms that declared stale-while-revalidate/stale-if-error directives are actually honored by the fronting cache, rather than trusting their presence in Cache-Control.",
	Tags:        []string{"stale-serving", "rfc5861"},
	DependsOn:   []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDCacheability)},
}

// Check runs the stale-serving behavior probe against each resource.
var Check = checkdef.NewResourceCheck(Def, run)

func run(ctx context.Context, target harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	pctx := target.Data.(*checkbase.ProbeCtx)

	dep, ok := store.GetForResource(checkbase.CheckIDCacheability, resource.ID)
	if !ok || dep.Skipped {
		return harnessx.Result{}, nil
	}
	analysis, ok := harnessx.DataAs[cacheability.AnalysisResult](dep)
	if !ok || !analysis.Cacheable {
		return harnessx.Result{}, nil
	}

	declared := DeclaredFrom(analysis.CacheControl)
	if !declared.Any() {
		return harnessx.Result{}, nil
	}

	req0, err := checkbase.NewRequest(ctx, resource.URL, pctx, nil)
	if err != nil {
		return harnessx.Result{}, err
	}
	base, err := checkbase.Do(ctx, pctx, req0)
	if err != nil {
		return harnessx.Result{}, err
	}

	var date time.Time
	if raw := base.Header.Get("Date"); raw != "" {
		if t, err := http.ParseTime(raw); err == nil {
			date = t
		}
	}

	res := Result{
		Declared:          declared,
		FreshnessLifetime: FreshnessLifetime(analysis.CacheControl, analysis.Expires, date),
	}
	var obs []harnessx.Observation

	if declared.StaleWhileRevalidate != nil {
		swrObs := testStaleWhileRevalidate(ctx, pctx, resource, &res, base)
		obs = append(obs, swrObs...)
	}

	if declared.StaleIfError != nil {
		sieObs := testStaleIfError(ctx, pctx, resource, &res, base)
		obs = append(obs, sieObs...)
	}

	for i := range obs {
		obs[i].CheckID = checkbase.CheckIDStaleServing
		obs[i].ResourceID = resource.ID
	}
	return harnessx.Result{Data: res, Observations: obs}, nil
}

// testStaleWhileRevalidate waits for the resource to enter its declared
// stale-while-revalidate window (bounded by ProbeCtx.StaleWindowMaxWait),
// then confirms the cache serves the prior stale response promptly instead
// of blocking on a synchronous origin refetch, and that a subsequent
// request shows evidence of the background revalidation actually happening.
func testStaleWhileRevalidate(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, res *Result, base checkbase.Exchange) []harnessx.Observation {
	if res.FreshnessLifetime <= 0 {
		return nil
	}

	age0 := AgeFromHeader(base.Header)
	wait := res.FreshnessLifetime - age0 + time.Second
	if wait <= 0 {
		wait = time.Second
	}
	if wait > pctx.StaleWindowMaxWait {
		res.WindowTooLargeToTest = true
		return []harnessx.Observation{{
			Title:       "stale-while-revalidate window too large to actively confirm",
			Description: fmt.Sprintf("the declared freshness lifetime (%s) exceeds the scan's stale-window test budget (%s, see --stale-window-max-wait) — directive presence/window is reported, but stale-serving behavior wasn't actively confirmed", res.FreshnessLifetime, pctx.StaleWindowMaxWait),
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityInfo},
		}}
	}

	if err := sleep(ctx, wait); err != nil {
		return nil
	}

	req1, err := checkbase.NewRequest(ctx, resource.URL, pctx, nil)
	if err != nil {
		return nil
	}
	stale, err := checkbase.Do(ctx, pctx, req1)
	if err != nil {
		return nil
	}

	var obs []harnessx.Observation

	honored := bytes.Equal(stale.Body, base.Body) && stale.Duration <= base.Duration*3+50*time.Millisecond
	res.SWRHonored = &honored
	if !honored {
		obs = append(obs, harnessx.Observation{
			Title:       "stale-while-revalidate not honored",
			Description: fmt.Sprintf("Cache-Control declares stale-while-revalidate=%d, but a request issued inside that window didn't receive the prior stale response promptly (took %s vs. a %s baseline, body changed=%v) — the fronting cache appears to block on synchronous revalidation instead of serving stale content", *res.Declared.StaleWhileRevalidate, stale.Duration, base.Duration, !bytes.Equal(stale.Body, base.Body)),
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityLow},
		})
		return obs
	}

	swrWindow := time.Duration(*res.Declared.StaleWhileRevalidate) * time.Second
	revalWait := swrWindow / 2
	if revalWait <= 0 || revalWait > pctx.StaleWindowMaxWait {
		revalWait = pctx.StaleWindowMaxWait
	}
	if err := sleep(ctx, revalWait); err != nil {
		return obs
	}

	req2, err := checkbase.NewRequest(ctx, resource.URL, pctx, nil)
	if err != nil {
		return obs
	}
	revalidated, err := checkbase.Do(ctx, pctx, req2)
	if err != nil {
		return obs
	}

	backgroundRevalidated := AgeFromHeader(revalidated.Header) < AgeFromHeader(stale.Header) || !bytes.Equal(revalidated.Body, stale.Body)
	res.SWRBackgroundRevalidated = &backgroundRevalidated
	if !backgroundRevalidated {
		obs = append(obs, harnessx.Observation{
			Title:       "stale-while-revalidate did not trigger a background refresh",
			Description: "stale content was served inside the stale-while-revalidate window, but a follow-up request after the expected revalidation delay still returned the same aged response — the declared background revalidation doesn't appear to be happening",
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityLow},
		})
	}
	return obs
}

// testStaleIfError only runs under --aggressive: confirming stale-if-error
// means asking the origin to fail, which — like the §5 security checks —
// is opt-in. It sends simulateErrorHeader and expects an instrumented
// origin/test fixture to return a failure; against a real, uninstrumented
// origin the header has no effect and the result stays inconclusive rather
// than being reported as either honored or not.
func testStaleIfError(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, res *Result, base checkbase.Exchange) []harnessx.Observation {
	if !pctx.Aggressive {
		return []harnessx.Observation{{
			Title:       "stale-if-error confirmation requires --aggressive",
			Description: "Cache-Control declares stale-if-error, but confirming it means simulating an origin failure — cache-detective only attempts that under --aggressive, and only against origins/fixtures that honor its simulated-failure probe header",
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityInfo},
		}}
	}

	req, err := checkbase.NewRequest(ctx, resource.URL, pctx, http.Header{simulateErrorHeader: {"1"}})
	if err != nil {
		return nil
	}
	forceErr, err := checkbase.Do(ctx, pctx, req)
	if err != nil {
		return nil
	}

	switch {
	case forceErr.StatusCode >= 500:
		honored := false
		res.SIEHonored = &honored
		return []harnessx.Observation{{
			Title:       "stale-if-error not honored",
			Description: fmt.Sprintf("Cache-Control declares stale-if-error=%d, but simulating an origin failure returned status %d instead of the last known-good stale response", *res.Declared.StaleIfError, forceErr.StatusCode),
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityMedium},
		}}
	case forceErr.StatusCode < 400 && bytes.Equal(forceErr.Body, base.Body):
		honored := true
		res.SIEHonored = &honored
		return nil
	default:
		// The origin didn't honor the simulated-failure probe header (still
		// answered normally with different content, or something in
		// between) — inconclusive, not a finding either way.
		return nil
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
