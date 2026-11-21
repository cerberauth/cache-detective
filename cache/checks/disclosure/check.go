// Package disclosure implements §10 of cache-detective: the cache-based
// information disclosure sweep, a broad, non-aggressive pass across every crawled
// resource, combining the cacheability check's (§1) parsed Cache-Control
// and captured body/Set-Cookie with the live cache-state check's (§2)
// observed HIT/MISS samples. Unlike cacheability.AuthDef/SessionDef, which
// flag a *declared* cacheability misconfiguration (the response's own
// headers say a shared cache may store it), this package flags what's
// actually been *observed* happening — a resource currently being served
// from cache that carries session-specific markers — and a second,
// narrower class cacheability.AuthDef/SessionDef don't cover at all: a
// PII/token-bearing JSON response missing the OWASP WSTG-ATHN-06
// no-store/no-cache guidance regardless of whether the request was
// authenticated.
//
// Every check here is read-only analysis of results two other checks
// already produced — no extra probe requests — so, unlike §5's
// exploitation-confirmation checks, it isn't gated behind
// ProbeCtx.Aggressive.
package disclosure

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
	"github.com/cerberauth/cache-detective/cache/checks/livestate"
)

const (
	disclosureTag = "security"
	wstgRef       = "OWASP WSTG-ATHN-06"

	cweCacheDisclosure = "CWE-524"
	owaspAccessControl = "A01:2021-Broken Access Control"
)

// Def describes the cache-based information disclosure sweep.
var Def = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDInfoDisclosure),
	Name:        "Cache-Based Information Disclosure Sweep",
	Description: "Broad, non-aggressive pass across every crawled resource: flags a response that's actually been observed as a live cache HIT while carrying Set-Cookie/CSRF/session markers, and flags a PII/token-bearing JSON response missing OWASP WSTG-ATHN-06's no-store/no-cache guidance regardless of authentication state. Pure analysis of the cacheability and live-state checks' own results — issues no extra requests.",
	Tags:        []string{disclosureTag, "information-disclosure"},
	CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
	CVSSScore:   8.6,
	CWEID:       cweCacheDisclosure,
	OWASP:       owaspAccessControl,
	DependsOn:   []string{string(checkbase.CheckIDCacheability), string(checkbase.CheckIDLiveState)},
}

// Check runs the disclosure sweep against each discovered resource.
var Check = checkdef.NewResourceCheck(Def, run)

func run(_ context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	analysis, ok := cacheabilityResult(store, resource.ID)
	if !ok {
		return harnessx.Result{Skipped: true, SkipReason: "cacheability result unavailable for resource"}, nil
	}

	var obs []harnessx.Observation
	if ob, found := checkLiveSessionDisclosure(store, resource, analysis); found {
		obs = append(obs, ob)
	}
	if ob, found := checkSensitiveJSONMissingNoStore(resource, analysis); found {
		obs = append(obs, ob)
	}

	return harnessx.Result{Observations: obs}, nil
}

// cacheabilityResult fetches and type-asserts the cacheability check's
// AnalysisResult for resourceID, the shared input both findings below read.
func cacheabilityResult(store harnessx.ResultStore, resourceID string) (cacheability.AnalysisResult, bool) {
	dep, ok := store.GetForResource(checkbase.CheckIDCacheability, resourceID)
	if !ok || dep.Skipped {
		return cacheability.AnalysisResult{}, false
	}
	return harnessx.DataAs[cacheability.AnalysisResult](dep)
}

// checkLiveSessionDisclosure flags a resource that's actually been
// observed as a live cache HIT (livestate, §2) while its response carries
// a Set-Cookie, CSRF token, or other session-specific marker
// (cacheability.DetectSensitiveData) — a shared cache confirmed to be
// replaying session-bound content, not just a theoretical misconfiguration
// per the response's own declared Cache-Control.
func checkLiveSessionDisclosure(store harnessx.ResultStore, resource harnessx.Resource, analysis cacheability.AnalysisResult) (harnessx.Observation, bool) {
	liveDep, ok := store.GetForResource(checkbase.CheckIDLiveState, resource.ID)
	if !ok || liveDep.Skipped {
		return harnessx.Observation{}, false
	}
	live, ok := harnessx.DataAs[livestate.AnalysisResult](liveDep)
	if !ok || live.HitCount == 0 {
		return harnessx.Observation{}, false
	}

	reasons := cacheability.DetectSensitiveData(analysis.Body, analysis.SetCookie)
	if len(reasons) == 0 {
		return harnessx.Observation{}, false
	}

	return harnessx.Observation{
		CheckID:    checkbase.CheckIDInfoDisclosure,
		ResourceID: resource.ID,
		Title:      "Shared cache is serving session-specific content",
		Description: fmt.Sprintf(
			"this resource was observed as a live cache HIT (%d of %d samples) while its response carries %s — per %s, session-specific/sensitive responses need Cache-Control: no-store and no-cache (ideally reinforced with must-revalidate, max-age=0, s-maxage=0) rather than relying on the cache to not store or replay them",
			live.HitCount, len(live.Samples), joinReasons(reasons), wstgRef,
		),
		Evidence: fmt.Sprintf("hit=%d/%d samples; %s", live.HitCount, len(live.Samples), joinReasons(reasons)),
		Metadata: map[string]string{checkbase.SeverityKey: checkbase.SeverityCritical},
	}, true
}

// checkSensitiveJSONMissingNoStore flags a JSON-looking response carrying
// PII/token material without both no-store and no-cache — the
// WSTG-ATHN-06 guidance — regardless of whether the request was
// authenticated: an unauthenticated API leaking *other* users' PII/tokens
// through a cache is exactly as real a disclosure as an authenticated
// endpoint doing so, and AuthDef/SessionDef only ever fire on
// authenticated or Set-Cookie-carrying responses respectively.
func checkSensitiveJSONMissingNoStore(resource harnessx.Resource, analysis cacheability.AnalysisResult) (harnessx.Observation, bool) {
	if !looksLikeJSON(analysis.Body) {
		return harnessx.Observation{}, false
	}
	reasons := cacheability.DetectSensitiveData(analysis.Body, nil)
	if len(reasons) == 0 {
		return harnessx.Observation{}, false
	}

	cc := analysis.CacheControl
	if cc.NoStore && cc.NoCache {
		return harnessx.Observation{}, false
	}

	defenseInDepth := "; consider also must-revalidate, max-age=0, and s-maxage=0 as defense-in-depth per " + wstgRef
	missing := "no-store"
	switch {
	case !cc.NoStore && !cc.NoCache:
		missing = "no-store and no-cache"
	case cc.NoStore:
		missing = "no-cache"
	}

	return harnessx.Observation{
		CheckID:     checkbase.CheckIDInfoDisclosure,
		ResourceID:  resource.ID,
		Title:       "Sensitive JSON response missing no-store/no-cache",
		Description: fmt.Sprintf("the JSON response carries %s but its Cache-Control is missing %s — per %s, a response carrying PII or token material needs both directives regardless of whether the request was authenticated%s", joinReasons(reasons), missing, wstgRef, defenseInDepth),
		Evidence:    fmt.Sprintf("cache-control=%q; %s", cc.Raw(), joinReasons(reasons)),
		Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityHigh},
	}, true
}

// looksLikeJSON is a cheap, dependency-free heuristic: a JSON response's
// body starts (after whitespace) with "{" or "[". AnalysisResult doesn't
// carry Content-Type, and a miss here just leaves a JSON response
// unchecked by this finding rather than suppressing something it
// shouldn't.
func looksLikeJSON(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

// joinReasons renders DetectSensitiveData's matched reasons into a single
// evidence/description fragment.
func joinReasons(reasons []string) string {
	return strings.Join(reasons, ", ")
}
