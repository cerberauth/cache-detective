package security

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// --- URL-parser discrepancy poisoning (§5) ----------------------------------

// URLParserDiscrepancyDef tests cache-vs-origin URL-parsing mismatches that
// let an attacker store an attacker-chosen response under an arbitrary
// cache key — "cache what/where" (Doyhenard, "Gotta cache 'em all", Black
// Hat USA 2024). Unlike KeyCollisionDef (which needs a static route that
// happens to answer 2xx for an arbitrary filename), the "what" here is
// supplied directly: a marker reflected via the unkeyed X-Forwarded-Host
// header, the same precondition UnkeyedHeaderCheck/UnkeyedImpactCheck
// exploit — so this check also demonstrates impact against dynamic/API
// origins with no exploitable static handler at all.
var URLParserDiscrepancyDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDURLParserDiscrepancy),
	Name:        "URL-Parser Discrepancy Poisoning",
	Description: "Tests cache-vs-origin path-parsing mismatches that let an attacker store a chosen response under an arbitrary cache key: a plain dot-segment key-normalization mismatch, its encoded-backslash (IIS-style) spelling, and — reusing DelimiterMapperCheck's confirmed per-origin quirks — an origin-only-delimiter composite and a cache-only-delimiter composite, each combined with dot-segment collapsing. The attacker-controlled \"what\" is a marker reflected via the unkeyed X-Forwarded-Host header; probed against a random, never-used victim path so no real entry is ever overwritten — the same technique reaches any cache key, including a high-value static one such as /main.js.",
	Tags:        []string{securityTag, cachePoisoningTag, cacheKeyTag},
	// DependsOn DelimiterMapperCheck specifically, not just CPDoSCheck (the
	// rest of this tail-of-chain group's dependency, e.g. KeyCollisionDef):
	// the delimiter composites below read cdn.DiscoveredQuirks, populated
	// by DelimiterMapperCheck for this origin, and harnessx only guarantees
	// that data is ready if this check is scheduled strictly after it.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDDelimiterMapper)},
	CVSSVector: cvssPoisoning,
	CVSSScore:  9.3,
	CWEID:      cweUnkeyedInput,
	OWASP:      owaspMisconfig,
}

var URLParserDiscrepancyCheck = checkdef.NewResourceCheck(URLParserDiscrepancyDef, runURLParserDiscrepancy)

func runURLParserDiscrepancy(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)
	budget := pctx.MaxAggressiveRequests

	u, err := url.Parse(resource.URL)
	if err != nil {
		return harnessx.Result{}, err
	}
	origin := u.Scheme + "://" + u.Host

	obs := probeKeyNormalizationPoisoning(ctx, pctx, resource, origin, &budget)

	quirks, ok := cdn.DiscoveredQuirks.Lookup(origin)
	if !ok {
		return harnessx.Result{Observations: obs}, nil
	}

	for _, d := range quirks.Delimiters {
		if !d.OriginOnly || quirks.CacheTraversal != cdn.NormalizesBeforeRules {
			continue
		}
		if ob, found := probeBackendDelimiterPoisoning(ctx, pctx, resource, origin, d.Delimiter, &budget); found {
			obs = append(obs, ob)
			break
		}
	}
	for _, d := range quirks.Delimiters {
		if !d.CacheOnly || quirks.OriginNormalizesTraversal == nil || !*quirks.OriginNormalizesTraversal {
			continue
		}
		if ob, found := probeFrontendDelimiterPoisoning(ctx, pctx, resource, origin, d.Delimiter, &budget); found {
			obs = append(obs, ob)
			break
		}
	}

	return harnessx.Result{Observations: obs}, nil
}

// keyNormalizationForms are the dot-segment spellings tried by
// probeKeyNormalizationPoisoning: a plain "/../", and the encoded-backslash
// "%5c..%5c" spelling IIS and some other platforms resolve identically to a
// forward slash. A normalizer that collapses one spelling but not the other
// is the same key-normalization discrepancy as the plain form, just reached
// through an alternate encoding — worth probing separately since a cache
// and an IIS origin don't have to agree on which spelling they recognize.
var keyNormalizationForms = []struct {
	name string
	up   string
}{
	{name: traversalFormPlain, up: "/../"},
	{name: "encoded-backslash", up: "%5c..%5c"},
}

// probeKeyNormalizationPoisoning tests the generic "cache what/where"
// pattern independent of any delimiter: a throwaway path segment ahead of a
// dot-segment traversal, reflecting a marker via an unkeyed header. If the
// cache collapses the traversal before computing its key (landing on the
// random victim's key) while the origin routes — and reflects the marker
// for — the full raw path, a plain follow-up request for the victim path
// alone replays the attacker's response. Every form uses its own random
// victim path, so — unlike CPDoS's single-slot-cache reasoning — trying
// every form costs no accuracy, only budget: each one is an independent,
// unrelated cache entry.
func probeKeyNormalizationPoisoning(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, origin string, budget *int) []harnessx.Observation {
	var obs []harnessx.Observation
	for _, form := range keyNormalizationForms {
		if *budget < 2 {
			break
		}
		victim := randomPathToken()
		poisonPath := "/" + randomPathToken() + form.up + victim
		poisonURL := origin + poisonPath

		*budget--
		poisoned, err := fetchExchangeWith(ctx, pctx, poisonURL, http.Header{headerXForwardedHost: {unkeyedInputMarker}})
		if err != nil || !reflectsMarker(poisoned) {
			continue
		}

		*budget--
		confirm, err := fetchExchange(ctx, pctx, origin+"/"+victim)
		if err != nil || !reflectsMarker(confirm) {
			continue
		}

		obs = append(obs, harnessx.Observation{
			CheckID:     checkbase.CheckIDURLParserDiscrepancy,
			ResourceID:  resource.ID,
			Title:       fmt.Sprintf("Cache-key normalization poisoning (%s traversal)", form.name),
			Description: fmt.Sprintf("a request to %q, reflecting an unkeyed X-Forwarded-Host marker, was answered by the origin, and a later plain request for the unrelated path /%s was served that same marker back — the cache normalized the %s dot-segment traversal before keying while the origin routed (and reflected) the full raw path, so an attacker-controlled response can be planted under any path's cache key, including a high-value one such as /main.js", poisonPath, victim, form.name),
			Evidence:    "poisoned: " + poisonURL + " ; replayed on: " + origin + "/" + victim,
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityCritical},
		})
	}
	return obs
}

// probeBackendDelimiterPoisoning composes a confirmed origin-only delimiter
// (the origin truncates its route there, ignoring everything after) with a
// "/../" traversal: /<payload><delimiter>/../<victim>. The origin routes
// (and reflects a marker for) <payload> alone, while the cache — confirmed
// to collapse dot-segments before keying (quirks.CacheTraversal ==
// NormalizesBeforeRules) — computes its key as if the delimiter and
// traversal were never there, landing the attacker's response under the
// plain victim path.
func probeBackendDelimiterPoisoning(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, origin, delim string, budget *int) (harnessx.Observation, bool) {
	if *budget < 2 {
		return harnessx.Observation{}, false
	}
	victim := randomPathToken()
	poisonPath := "/" + randomPathToken() + delim + "/../" + victim
	poisonURL := origin + poisonPath

	*budget--
	poisoned, err := fetchExchangeWith(ctx, pctx, poisonURL, http.Header{headerXForwardedHost: {unkeyedInputMarker}})
	if err != nil || !reflectsMarker(poisoned) {
		return harnessx.Observation{}, false
	}

	*budget--
	confirm, err := fetchExchange(ctx, pctx, origin+"/"+victim)
	if err != nil || !reflectsMarker(confirm) {
		return harnessx.Observation{}, false
	}

	return harnessx.Observation{
		CheckID:     checkbase.CheckIDURLParserDiscrepancy,
		ResourceID:  resource.ID,
		Title:       fmt.Sprintf("Cache-key poisoning via back-end delimiter %q", delim),
		Description: fmt.Sprintf("combining the confirmed origin-only delimiter %q with a \"/../\" traversal: the origin ignored everything from %q onward — routing, and reflecting an unkeyed header marker for, the attacker-chosen prefix alone — while the cache, confirmed to collapse dot-segments before keying, computed its key as if the delimiter and traversal were never there, landing the attacker's response under the plain victim path's cache key. The same technique reaches any cache key, including a high-value static one such as /main.js", delim, delim),
		Evidence:    "poisoned: " + poisonURL + " ; replayed on: " + origin + "/" + victim,
		Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityCritical},
	}, true
}

// probeFrontendDelimiterPoisoning composes a confirmed cache-only delimiter
// (the cache truncates its key there, ignoring everything after) with a
// "/../" traversal: /<victim><delimiter>/../<payload>. The cache keys the
// request as the plain victim path alone, while the origin — confirmed to
// collapse dot-segment traversal (quirks.OriginNormalizesTraversal) —
// routes past the victim segment entirely and reflects a marker for
// <payload> instead. A plain request for the victim path then replays that
// attacker-controlled response.
func probeFrontendDelimiterPoisoning(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, origin, delim string, budget *int) (harnessx.Observation, bool) {
	if *budget < 2 {
		return harnessx.Observation{}, false
	}
	victim := randomPathToken()
	poisonPath := "/" + victim + delim + "/../" + randomPathToken()
	poisonURL := origin + poisonPath

	*budget--
	poisoned, err := fetchExchangeWith(ctx, pctx, poisonURL, http.Header{headerXForwardedHost: {unkeyedInputMarker}})
	if err != nil || !reflectsMarker(poisoned) {
		return harnessx.Observation{}, false
	}

	*budget--
	confirm, err := fetchExchange(ctx, pctx, origin+"/"+victim)
	if err != nil || !reflectsMarker(confirm) {
		return harnessx.Observation{}, false
	}

	return harnessx.Observation{
		CheckID:     checkbase.CheckIDURLParserDiscrepancy,
		ResourceID:  resource.ID,
		Title:       fmt.Sprintf("Cache-key poisoning via front-end delimiter %q", delim),
		Description: fmt.Sprintf("combining the confirmed cache-only delimiter %q with a \"/../\" traversal: the cache truncated its key at %q — keying the request as the plain victim path alone — while the origin, confirmed to collapse dot-segment traversal, routed past the victim segment entirely and reflected an unkeyed header marker for the attacker-chosen path instead. A plain request for the victim path now replays that attacker-controlled response — the same technique reaches any cache key, including a high-value static one such as /main.js", delim, delim),
		Evidence:    "poisoned: " + poisonURL + " ; replayed on: " + origin + "/" + victim,
		Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityCritical},
	}, true
}
