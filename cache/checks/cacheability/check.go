package cacheability

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
)

// cacheabilityTag is applied to every CheckDef in this package.
const (
	cacheabilityTag = "cacheability"
	rfc9111Tag      = "rfc9111"
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
	Tags:        []string{cacheabilityTag, rfc9111Tag},
	// DependsOn CPDoSCheck (the tail of the §5 ordering chain — see
	// security.CPDoSDef), not just Discovery: this check's own baseline
	// request is a plain, unpoisoned GET, and harnessx runs same-level
	// checks concurrently. Against a target with a single-slot
	// (low-cardinality) cache, that plain GET can win the race and
	// permanently fill the slot with a clean response before a poisoning
	// check gets a chance to plant its own — masking a real finding.
	DependsOn: []string{
		string(checkbase.CheckIDDiscovery),
		string(checkbase.CheckIDCPDoS),
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
	Tags:        []string{cacheabilityTag, "security", rfc9111Tag},
	CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
	CVSSScore:   8.1,
	CWEID:       "CWE-524",
	OWASP:       "A01:2021-Broken Access Control",
	DependsOn:   []string{string(checkbase.CheckIDCacheability)},
}

// SessionDef describes the cacheable-session-material security check: the
// unauthenticated-request counterpart of AuthDef. A response that mints a
// cookie (a session id, a CSRF cookie) but is cacheable lets a shared cache
// store the first caller's Set-Cookie and replay it, verbatim, to everyone
// who follows — handing them that caller's session.
var SessionDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDSessionCacheable),
	Name:        "Cacheable Response Sets a Cookie",
	Description: "Flags a cacheable response that carries Set-Cookie without Cache-Control: private or no-store. A shared cache that stores it replays the first caller's cookie (and any session-bound CSRF token in the body) to every later caller. Severity escalates for session-looking cookie names and for tokens/credentials in the body.",
	Tags:        []string{cacheabilityTag, "security", rfc9111Tag},
	CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
	CVSSScore:   8.6,
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

// SessionCheck depends on Check and turns a cacheable response carrying
// Set-Cookie into a standalone, severity-bearing finding.
var SessionCheck = checkdef.NewResourceCheck(SessionDef, runSession)

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

	analysis := Analyze(ex.Method, ex.StatusCode, ex.Header, checkbase.IsAuthenticated(resource.URL, pctx))
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

	if !authViolation(analysis) {
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

// authViolation reports whether analysis is an authenticated response a
// shared cache may store without the RFC 9111 §3.5 opt-in: the condition
// AuthCheck reports on.
func authViolation(analysis AnalysisResult) bool {
	cc := analysis.CacheControl
	if !analysis.Authenticated || !analysis.Cacheable || cc.Private || cc.NoStore {
		return false
	}
	// RFC 9111 §3.5: must-revalidate, public, or s-maxage on the response
	// explicitly opts a shared cache back into storing it despite the
	// request carrying Authorization. Any other combination is a violation.
	return !cc.MustRevalidate && !cc.Public && cc.SMaxAge == nil
}

func runSession(_ context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	dep, ok := store.GetForResource(checkbase.CheckIDCacheability, resource.ID)
	if !ok || dep.Skipped {
		return harnessx.Result{Skipped: true, SkipReason: "cacheability result unavailable for resource"}, nil
	}
	analysis, ok := harnessx.DataAs[AnalysisResult](dep)
	if !ok {
		return harnessx.Result{Skipped: true, SkipReason: "cacheability result carried no analysis data"}, nil
	}

	cc := analysis.CacheControl
	if !analysis.Cacheable || cc.Private || cc.NoStore || len(analysis.SetCookie) == 0 {
		return harnessx.Result{}, nil
	}
	// AuthCheck already reports this response (and escalates on Set-Cookie);
	// a second finding for the same defect would just be noise.
	if authViolation(analysis) {
		return harnessx.Result{}, nil
	}

	severity := checkbase.SeverityMedium
	if setCookieLooksLikeSession(analysis.SetCookie) {
		severity = checkbase.SeverityHigh
	}
	description := "the response is cacheable and sets a cookie, without Cache-Control: private or no-store — a shared cache that stores it replays the first caller's Set-Cookie to every later caller"
	evidence := fmt.Sprintf("cache-control=%q; set-cookie: %s", cc.Raw(), cookieNames(analysis.SetCookie))

	// Anything in the body beyond the cookie itself (a CSRF token, a JWT, a
	// credential field) is replayed alongside it.
	var bodyReasons []string
	for _, r := range DetectSensitiveData(analysis.Body, nil) {
		if r != "email address found in response body" {
			bodyReasons = append(bodyReasons, r)
		}
	}
	if len(bodyReasons) > 0 {
		severity = checkbase.SeverityCritical
		description += "; the body also carries token/credential material that would be replayed with it: " + joinReasons(bodyReasons)
		evidence += "; " + joinReasons(bodyReasons)
	}

	return harnessx.Result{Observations: []harnessx.Observation{{
		CheckID:     checkbase.CheckIDSessionCacheable,
		ResourceID:  resource.ID,
		Title:       "Cacheable response sets a cookie",
		Description: description,
		Evidence:    evidence,
		Metadata:    map[string]string{checkbase.SeverityKey: severity},
	}}}, nil
}

// sessionCookieName matches cookie names that conventionally carry a
// session, auth state, or CSRF secret. Deliberately a name heuristic — a
// miss leaves the finding at its base severity, it never suppresses it.
var sessionCookieName = regexp.MustCompile(`(?i)(sess|sid|auth|token|jwt|csrf|xsrf|login|remember)`)

func setCookieLooksLikeSession(setCookie []string) bool {
	for _, sc := range setCookie {
		name, _, _ := strings.Cut(sc, "=")
		if sessionCookieName.MatchString(name) {
			return true
		}
	}
	return false
}

// cookieNames lists just the names from Set-Cookie header values, so the
// evidence string never echoes a live session value into a report.
func cookieNames(setCookie []string) string {
	names := make([]string, 0, len(setCookie))
	for _, sc := range setCookie {
		name, _, _ := strings.Cut(sc, "=")
		names = append(names, strings.TrimSpace(name))
	}
	return strings.Join(names, ", ")
}
