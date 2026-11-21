package security

import (
	"context"
	"fmt"
	"net/url"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
)

// --- Delimiter-based cache deception (§5) ----------------------------------

// DelimiterDeceptionDef describes the delimiter-based cache deception
// check: unlike CacheDeceptionDef's fixed, blind list of candidate
// delimiters, this one only tests delimiters DelimiterMapperCheck has
// already *confirmed* the target's origin treats as a path delimiter
// (cdn.DiscoveredQuirks) — so every probe here targets a discrepancy known
// to exist on this specific target, rather than a guess.
var DelimiterDeceptionDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDDelimiterDeception),
	Name:        "Delimiter-Based Cache Deception",
	Description: "For each origin-only path delimiter the delimiter mapper confirmed for this target, probes <dynamic-path><delimiter><static-looking-suffix> in both the delimiter's encoded and unencoded forms, and checks whether the cache stores the resulting (potentially private) response under that URL (Doyhenard 2024; PortSwigger Academy web-cache-deception labs).",
	Tags:        []string{securityTag, cacheDeceptionTag},
	// DependsOn both DelimiterMapperCheck (whose cdn.DiscoveredQuirks
	// record this check reads — it needs to have already run for this
	// origin) and CacheDeceptionCheck (the tail of the §5 ordering chain at
	// the time DelimiterMapperDef was written): this check's own baseline
	// request targets the resource's canonical URL, and harnessx runs
	// same-level checks concurrently, so it needs the same serialization
	// against the resource's canonical entry the rest of the chain uses —
	// see CacheDeceptionDef's own DependsOn comment.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDDelimiterMapper), string(checkbase.CheckIDCacheDeception)},
	CVSSVector: cvssDeception,
	CVSSScore:  8.1,
	CWEID:      cweCacheDeception,
	OWASP:      owaspAccessControl,
}

var DelimiterDeceptionCheck = checkdef.NewResourceCheck(DelimiterDeceptionDef, runDelimiterDeception)

// delimiterDeceptionSuffixes are the static-looking suffixes tried after a
// confirmed delimiter. Kept short (unlike CacheDeceptionCheck's full
// per-CDN extension sweep): the novel surface this check probes is which
// *delimiters* work, already narrowed to the ones DelimiterMapperCheck
// confirmed, so a handful of common static extensions is enough to confirm
// each one also triggers deception.
var delimiterDeceptionSuffixes = []string{".css", ".js", ".png"}

func runDelimiterDeception(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)

	quirks, ok := cdn.DiscoveredQuirks.Lookup(originOf(resource.URL))
	if !ok {
		return harnessx.Result{}, nil
	}
	var confirmed []string
	for _, d := range quirks.Delimiters {
		if d.OriginOnly {
			confirmed = append(confirmed, d.Delimiter)
		}
	}
	if len(confirmed) == 0 {
		return harnessx.Result{}, nil
	}

	base, err := fetchExchange(ctx, pctx, resource.URL)
	if err != nil {
		return harnessx.Result{}, err
	}

	budget := pctx.MaxAggressiveRequests
	authenticated := checkbase.IsAuthenticated(resource.URL, pctx)
	var obs []harnessx.Observation
	found := map[string]bool{}
	for _, delim := range confirmed {
		for _, form := range delimiterForms(delim) {
			for _, suffix := range delimiterDeceptionSuffixes {
				if budget <= 0 {
					return harnessx.Result{Observations: obs}, nil
				}
				if found[delim] {
					// One confirmed suffix per delimiter is enough to prove
					// it's a live deception surface; spend the remaining
					// budget on the other confirmed delimiters instead.
					break
				}
				budget--

				deceptiveURL := appendPathSuffix(resource.URL, form+suffix)
				ex, err := fetchExchange(ctx, pctx, deceptiveURL)
				if err != nil || !sameResponse(base, ex) || !cacheableResponse(ex.Method, ex.StatusCode, ex.Header) {
					continue
				}

				// Same "report distinctly from a generic public match"
				// reasoning as the classic-WCD check: a cache matching the
				// baseline isn't itself a vulnerability unless the content
				// it would store is confirmed private.
				reasons := cacheability.DetectSensitiveData(base.Body, base.Header.Values("Set-Cookie"))
				if !authenticated && len(reasons) == 0 {
					continue
				}
				severity := checkbase.SeverityMedium
				sensitivity := "the request carried credentials (bearer token or cookie), so the stored response is tied to that session even without an obvious PII/token marker in the body"
				if len(reasons) > 0 {
					severity = checkbase.SeverityHigh
					sensitivity = "the response carries " + joinReasons(reasons)
				}
				if authenticated && len(reasons) > 0 {
					severity = checkbase.SeverityCritical
				}

				found[delim] = true
				obs = append(obs, harnessx.Observation{
					CheckID:     checkbase.CheckIDDelimiterDeception,
					ResourceID:  resource.ID,
					Title:       "Cache deception via confirmed origin delimiter",
					Description: fmt.Sprintf("the delimiter mapper confirmed %q as an origin-only path delimiter on this target; appending it plus the static-looking suffix %q (form %q) still served the original response, and that response looks cacheable — %s, not a generic page anyone could already reach", delim, suffix, form, sensitivity),
					Evidence:    "probed: " + deceptiveURL,
					Metadata:    map[string]string{checkbase.SeverityKey: severity},
				})
			}
		}
	}

	return harnessx.Result{Observations: obs}, nil
}

// delimiterForms returns the forms of delim to try: delim itself, plus its
// encoded counterpart for a single raw character (";" -> "%3B") or its
// decoded counterpart for an already-percent-encoded one ("%00" -> the raw
// byte) — covering both directions a cache/origin pair might disagree on
// which form is "the same" delimiter. Falls back to just delim when neither
// transform applies cleanly.
func delimiterForms(delim string) []string {
	if len(delim) == 3 && delim[0] == '%' {
		if decoded, err := url.PathUnescape(delim); err == nil && decoded != delim {
			return []string{delim, decoded}
		}
		return []string{delim}
	}
	if len(delim) == 1 {
		return []string{delim, fmt.Sprintf("%%%02X", delim[0])}
	}
	return []string{delim}
}
