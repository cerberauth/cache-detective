package cacheability

import (
	"context"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
)

// Def describes the cacheability-analysis check. It carries no CVSS score:
// most of its findings (conflicting directives, missing validators) are
// informational, not vulnerabilities in their own right. The one
// security-relevant misconfiguration it can surface — an authenticated
// response marked cacheable — is reported by AuthDef/AuthCheck instead, so
// that finding can carry distinct, real severity metadata.
var Def = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDCacheability),
	Name:        "Cacheability Analysis",
	Description: "Parses Cache-Control/Expires/Pragma/Vary and RFC 9111 status/method defaults to determine whether a response is cacheable, flagging conflicting directives and missing validators.",
	Tags:        []string{"cacheability", "rfc9111"},
	DependsOn:   []string{string(checkbase.CheckIDDiscovery)},
}

// AuthDef describes the authenticated-cacheable security check.
var AuthDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDAuthCacheable),
	Name:        "Authenticated Response Marked Cacheable",
	Description: "Flags a response sent with credentials (bearer token or cookies) that is nonetheless cacheable by shared caches — a common cause of cross-user information disclosure.",
	Tags:        []string{"cacheability", "security"},
	CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
	CVSSScore:   8.1,
	CWEID:       "CWE-524",
	OWASP:       "A01:2021-Broken Access Control",
	DependsOn:   []string{string(checkbase.CheckIDCacheability)},
}

// Check runs the cacheability analysis against each discovered resource,
// storing the AnalysisResult as Result.Data for AuthCheck (and future
// checks, e.g. live-state's cross-check against declared freshness) to
// reuse without a second request.
var Check = checkdef.NewResourceCheck(Def, run)

// AuthCheck depends on Check and turns an authenticated-but-cacheable
// AnalysisResult into a standalone, severity-bearing finding.
var AuthCheck = checkdef.NewResourceCheck(AuthDef, runAuth)

func run(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	pctx := target.Data.(*checkbase.ProbeCtx)
	req, err := checkbase.NewRequest(ctx, resource.URL, pctx, nil)
	if err != nil {
		return harnessx.Result{}, err
	}
	ex, err := checkbase.Do(ctx, pctx, req)
	if err != nil {
		return harnessx.Result{}, err
	}

	analysis := Analyze(ex.Method, ex.StatusCode, ex.Header, pctx.Authenticated)
	obs := analysis.Findings
	for i := range obs {
		obs[i].CheckID = checkbase.CheckIDCacheability
		obs[i].ResourceID = resource.ID
	}
	return harnessx.Result{Data: analysis, Observations: obs}, nil
}

func runAuth(_ context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	dep, ok := store.GetForResource(checkbase.CheckIDCacheability, resource.ID)
	if !ok || dep.Skipped {
		return harnessx.Result{Skipped: true, SkipReason: "cacheability result unavailable for resource"}, nil
	}
	analysis, ok := harnessx.DataAs[AnalysisResult](dep)
	if !ok {
		return harnessx.Result{Skipped: true, SkipReason: "cacheability result carried no analysis data"}, nil
	}

	if !analysis.Authenticated || !analysis.Cacheable || analysis.CacheControl.Private || analysis.CacheControl.NoStore {
		return harnessx.Result{}, nil
	}

	obs := harnessx.Observation{
		CheckID:     checkbase.CheckIDAuthCacheable,
		ResourceID:  resource.ID,
		Title:       "Authenticated response marked cacheable",
		Description: "the request carried credentials (bearer token or cookie) but the response has no Cache-Control: private/no-store, so a shared cache/CDN in front of the origin may serve it to other users",
		Evidence:    analysis.CacheControl.Raw(),
	}
	return harnessx.Result{Observations: []harnessx.Observation{obs}}, nil
}
