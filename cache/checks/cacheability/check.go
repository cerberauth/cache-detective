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
	// DependsOn ResponseSplittingCheck (the tail of the §5 ordering chain —
	// see security.ResponseSplittingDef), not just Discovery: this check's
	// own baseline request is a plain, unpoisoned GET, and harnessx runs
	// same-level checks concurrently. Against a target with a single-slot
	// (low-cardinality) cache, that plain GET can win the race and
	// permanently fill the slot with a clean response before a poisoning
	// check gets a chance to plant its own — masking a real finding.
	DependsOn: []string{
		string(checkbase.CheckIDDiscovery),
		string(checkbase.CheckIDResponseSplitting),
	},
}

// AuthDef describes the authenticated-cacheable security check: RFC 9111
// §3.5 — a shared cache MUST NOT store a response to a request carrying
// Authorization unless the response itself carries must-revalidate, public,
// or s-maxage, explicitly opting back in.
var AuthDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDAuthCacheable),
	Name:        "Authenticated Response Marked Cacheable",
	Description: "Flags a response sent with credentials (bearer token or cookies) that a shared cache may store despite carrying none of the RFC 9111 §3.5 opt-in directives (must-revalidate, public, s-maxage) — a common cause of cross-user information disclosure. Severity escalates when the response body/headers carry PII, tokens, or Set-Cookie.",
	Tags:        []string{"cacheability", "security", "rfc9111"},
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
	analysis.Body = ex.Body
	analysis.SetCookie = ex.Header.Values("Set-Cookie")
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

	cc := analysis.CacheControl
	if !analysis.Authenticated || !analysis.Cacheable || cc.Private || cc.NoStore {
		return harnessx.Result{}, nil
	}
	// RFC 9111 §3.5: must-revalidate, public, or s-maxage on the response
	// explicitly opts a shared cache back into storing it despite the
	// request carrying Authorization. Any other combination is a violation.
	if cc.MustRevalidate || cc.Public || cc.SMaxAge != nil {
		return harnessx.Result{}, nil
	}

	severity := checkbase.SeverityHigh
	description := "the request carried credentials (bearer token or cookie) and the response is cacheable but carries none of the RFC 9111 §3.5 opt-in directives (must-revalidate, public, s-maxage) — a shared cache/CDN in front of the origin may store and serve it to other users"
	evidence := analysis.CacheControl.Raw()

	if reasons := DetectSensitiveData(analysis.Body, analysis.SetCookie); len(reasons) > 0 {
		severity = checkbase.SeverityCritical
		description += "; the response also carries sensitive content that would be exposed to other users if cached: " + joinReasons(reasons)
		evidence += "; " + joinReasons(reasons)
	}

	obs := harnessx.Observation{
		CheckID:     checkbase.CheckIDAuthCacheable,
		ResourceID:  resource.ID,
		Title:       "Authenticated response marked cacheable",
		Description: description,
		Evidence:    evidence,
		Metadata:    map[string]string{checkbase.SeverityKey: severity},
	}
	return harnessx.Result{Observations: []harnessx.Observation{obs}}, nil
}

func joinReasons(reasons []string) string {
	out := reasons[0]
	for _, r := range reasons[1:] {
		out += ", " + r
	}
	return out
}
