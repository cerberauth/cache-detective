package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// --- Delimiter & path-normalization discrepancy mapping (§5) ----------------

var DelimiterMapperDef = checkbase.CheckDef{
	ID:   string(checkbase.CheckIDDelimiterMapper),
	Name: "Delimiter & Normalization Discrepancy Mapper",
	Description: "Maps characters the origin treats as a path delimiter (truncating its route there) but a fronting cache keys on verbatim, characters the cache truncates its key at but the origin routes on in full, plus whether the origin collapses encoded/plain dot-segment traversal and whether the cache normalizes that traversal before or after applying its cache rules — the foundation discrepancy behind both cache-key poisoning and cache deception (Doyhenard, \"Gotta cache 'em all\", Black Hat USA 2024). " +
		"Per-origin results are recorded in the CDN quirk store (cdn.DiscoveredQuirks) for reuse.",
	Tags: []string{securityTag, cacheDeceptionTag, cacheKeyTag},
	// DependsOn CPDoSCheck, the tail of the §5 poison chain (see CPDoSDef):
	// this check issues a plain baseline GET against the resource's canonical
	// URL (R0) plus suffixed/delimited variants, and harnessx runs same-level
	// checks concurrently. Serializing it after the poison chain keeps those
	// requests from landing between another §5 check's poison/confirm pair and
	// masking its finding — the same reasoning the rest of the chain documents.
	// It joins at the same level as varykey (which also depends on CPDoSCheck):
	// both are read-only against the canonical entry, so running concurrently
	// is safe.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDCPDoS)},
	CVSSVector: cvssDeception,
	CVSSScore:  8.1,
	CWEID:      cweCacheDeception,
	OWASP:      owaspAccessControl,
}

var DelimiterMapperCheck = checkdef.NewResourceCheck(DelimiterMapperDef, runDelimiterMapper)

// delimiterCandidates are characters inserted between the real path and a
// random suffix in the baseline/suffix/insert probe (Doyhenard 2024): if the
// origin truncates its route at the character it serves the baseline response
// back, while a cache that keys on the verbatim request path stores that
// response under the distinct, attacker-chosen URL. The percent-encoded forms
// (%00/%0a/%23/%5c) are sent on the wire as those literal bytes — Go preserves
// a valid percent-encoding in the request path — so the probe tests how origin
// and cache each treat the encoded octet, not a decoded one. A bare "#" from
// the issue's candidate list is intentionally omitted: a spec-compliant client
// can't send an unencoded fragment delimiter in the path (it's stripped as a
// fragment, never reaching the wire), so "%23" covers the only transmittable
// form. "../"/"..%2f" are handled by probeNormalization below, since they test
// dot-segment collapsing rather than single-character truncation.
// Dot-segment spellings spliced between the throwaway segment and the
// resource's final segment by insertTraversalDetour.
const (
	plainTraversal   = "/../"
	encodedTraversal = "/..%2f"
)

var delimiterCandidates = []string{";", ".", "$", "%00", "%0a", "%23", "%5c"}

func runDelimiterMapper(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)

	// R0: the undelimited baseline. Every delimiter/traversal variant is
	// compared against this exact response.
	base, err := fetchExchange(ctx, pctx, resource.URL)
	if err != nil {
		return harnessx.Result{}, err
	}

	budget := pctx.MaxAggressiveRequests
	mapping := cdn.TargetQuirks{Origin: originOf(resource.URL)}
	var obs []harnessx.Observation

	// Spend the request budget in priority order: the origin-side sweep and
	// traversal probe first, then the two probes that each cost extra requests
	// per finding (cache-side normalization order, cache-only delimiters), so a
	// tight --max-aggressive-requests never starves the cheaper, primary probes.
	sweepObs, suffix, reverse := mapDelimiters(ctx, pctx, resource, base, &budget, &mapping)
	obs = append(obs, sweepObs...)
	obs = append(obs, probeNormalization(ctx, pctx, resource, base, &budget, &mapping)...)
	obs = append(obs, probeCacheNormalizationOrder(ctx, pctx, resource, base, &budget, &mapping)...)
	for _, d := range reverse {
		if o, ok := probeCacheOnlyDelimiter(ctx, pctx, resource, base, d, suffix, &budget, &mapping); ok {
			obs = append(obs, o)
		}
	}

	// Record even an all-negative mapping: a later resource under this origin
	// (or an embedding tool) can then see the origin was probed and found
	// clean, rather than re-running the sweep.
	cdn.DiscoveredQuirks.Record(mapping)

	return harnessx.Result{Data: mapping, Observations: obs}, nil
}

// fetchSuffixed requests resourceURL with suffix appended to its path, under a
// fresh cache-buster so the request is answered by the origin's routing of
// that exact path. Without it a cache that truncates its key at a delimiter
// would replay the cached baseline for the delimited URL, which the sweep
// would misread as an origin-only delimiter. It returns the URL sent.
func fetchSuffixed(ctx context.Context, pctx *checkbase.ProbeCtx, resourceURL, suffix string) (checkbase.Exchange, string, error) {
	bp, err := checkbase.NewCacheBusterProbe(resourceURL, pctx)
	if err != nil {
		return checkbase.Exchange{}, "", err
	}
	suffixedURL := appendPathSuffix(bp.URL, suffix)
	ex, err := fetchExchangeWith(ctx, pctx, suffixedURL, bp.Header)
	return ex, suffixedURL, err
}

// mapDelimiters runs the baseline/suffix/insert sweep across
// delimiterCandidates. It first sends R1 (a plain random suffix, no
// delimiter): if the origin serves the baseline response back even for that
// unrouteable path, it ignores trailing path junk wholesale, so a later
// R2 == R0 match can't be attributed to any specific delimiter and the sweep
// is abandoned. A candidate whose R2 differs from R0 is not origin-only; it is
// returned (with the suffix it was probed under) for probeCacheOnlyDelimiter to
// check in the reverse direction once the primary probes have had their budget.
func mapDelimiters(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, base checkbase.Exchange, budget *int, mapping *cdn.TargetQuirks) (obs []harnessx.Observation, suffix string, reverse []string) {
	if *budget <= 0 {
		return nil, "", nil
	}
	suffix = randomPathToken()

	*budget--
	r1, _, err := fetchSuffixed(ctx, pctx, resource.URL, suffix)
	if err != nil {
		return nil, "", nil
	}
	if sameResponse(base, r1) {
		// Origin ignores trailing path junk — the probe can't isolate a
		// delimiter's effect, so don't guess.
		return nil, "", nil
	}

	for _, d := range delimiterCandidates {
		if *budget <= 0 {
			break
		}
		*budget--

		r2, r2URL, err := fetchSuffixed(ctx, pctx, resource.URL, d+suffix)
		if err != nil {
			continue
		}
		if !sameResponse(base, r2) {
			reverse = append(reverse, d)
			continue
		}

		cacheable := cacheableResponse(r2.Method, r2.StatusCode, r2.Header)
		mapping.Delimiters = append(mapping.Delimiters, cdn.DelimiterDiscrepancy{
			Delimiter:  d,
			OriginOnly: true,
			Cacheable:  cacheable,
		})

		severity := checkbase.SeverityMedium
		cacheNote := "the response wasn't obviously cacheable, so confirm the fronting cache stores it before treating this as exploitable"
		if cacheable {
			severity = checkbase.SeverityHigh
			cacheNote = "and that response looks cacheable — a live cache-deception surface if the undelimited resource carries sensitive/authenticated content"
		}
		obs = append(obs, harnessx.Observation{
			CheckID:     checkbase.CheckIDDelimiterMapper,
			ResourceID:  resource.ID,
			Title:       fmt.Sprintf("Origin-only path delimiter %q", d),
			Description: fmt.Sprintf("inserting %q before a random path suffix still served the undelimited resource's (identical) response — the origin truncates its route at %q while a cache keying on the verbatim request path would store that response under the distinct URL; %s", d, d, cacheNote),
			Evidence:    "probed: " + r2URL,
			Metadata:    map[string]string{checkbase.SeverityKey: severity},
		})
	}
	return obs, suffix, reverse
}

// probeCacheOnlyDelimiter tests the reverse direction for a candidate the
// origin does not treat as a delimiter (R2 != R0): does the *cache* truncate
// its key at d? The probe runs on a cache-buster-isolated entry, so it never
// touches the resource's real cache entry:
//
//	A = <resource>?<buster> + d + suffix   (the origin routes on the full path
//	                                         and answers with something other
//	                                         than R0, typically a 404)
//	C = <resource>?<buster>                 (the undelimited URL, same buster)
//
// If C is then answered with A's response, the cache keyed A under C's key —
// it dropped everything from d onward. The attacker consequence is cache
// poisoning: any response the origin can be made to return for the delimited
// URL (an error, a reflected value) replaces the canonical resource for every
// visitor. Two requests per candidate, only spent when budget allows.
func probeCacheOnlyDelimiter(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, base checkbase.Exchange, d, suffix string, budget *int, mapping *cdn.TargetQuirks) (harnessx.Observation, bool) {
	if *budget < 2 {
		return harnessx.Observation{}, false
	}
	bp, err := checkbase.NewCacheBusterProbe(resource.URL, pctx)
	if err != nil {
		return harnessx.Observation{}, false
	}
	delimitedURL := appendPathSuffix(bp.URL, d+suffix)

	*budget--
	a, err := fetchExchangeWith(ctx, pctx, delimitedURL, bp.Header)
	// A 5xx is never stored by a sane cache, and a response equal to R0 is the
	// origin-only case handled by the caller.
	if err != nil || a.StatusCode >= http.StatusInternalServerError || sameResponse(base, a) {
		return harnessx.Observation{}, false
	}

	*budget--
	c, err := fetchExchangeWith(ctx, pctx, bp.URL, bp.Header)
	if err != nil || !sameResponse(a, c) || sameResponse(base, c) {
		return harnessx.Observation{}, false
	}

	mapping.Delimiters = append(mapping.Delimiters, cdn.DelimiterDiscrepancy{
		Delimiter: d,
		CacheOnly: true,
		Cacheable: true,
	})
	return harnessx.Observation{
		CheckID:     checkbase.CheckIDDelimiterMapper,
		ResourceID:  resource.ID,
		Title:       fmt.Sprintf("Cache-only path delimiter %q", d),
		Description: fmt.Sprintf("a request to the resource followed by %q and a random suffix was answered by the origin with a response different from the resource's, yet a plain request to the resource (same cache-buster) was then served that very response — the cache truncates its key at %q while the origin routes on the full path. Any response the origin can be made to return for a %q-delimited URL (an error page, a reflected value) is stored under, and replayed for, the undelimited resource: cache poisoning / denial of service", d, d, d),
		Evidence:    "poisoned: " + delimitedURL + " ; replayed on: " + bp.URL,
		Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityHigh},
	}, true
}

// probeNormalization tests whether the origin collapses dot-segment traversal,
// encoded ("..%2f") and plain ("../"). The probe inserts a nonexistent
// intermediate segment that a traversal step pops back off — /dir/<rand>/../base
// resolves to the original /dir/base only if the server normalizes the
// dot-segment. An origin that normalizes while a fronting cache keys on the
// verbatim detour path is the "normalize before vs. after cache rules"
// discrepancy (CloudFront/Azure/Imperva normalize before; Cloudflare/Google
// Cloud/Fastly do not) — the cache stores the origin's real response under the
// detour URL.
func probeNormalization(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, base checkbase.Exchange, budget *int, mapping *cdn.TargetQuirks) []harnessx.Observation {
	seg := randomPathToken()
	var obs []harnessx.Observation

	probes := []struct {
		delim    string
		encoded  bool
		title    string
		severity string
		detail   string
		dst      **bool
	}{
		{
			delim:    encodedTraversal,
			encoded:  true,
			title:    "Origin normalizes encoded path traversal",
			severity: checkbase.SeverityHigh,
			detail:   "the origin decoded and collapsed an encoded %2f dot-segment back to the resource — a cache that keys on the verbatim (un-normalized) request path, as Cloudflare/Google Cloud/Fastly do by default, would store the origin's response under the distinct detour URL (web cache deception); caches that normalize before applying cache rules, like CloudFront/Azure/Imperva, are not affected",
			dst:      &mapping.OriginNormalizesEncodedTraversal,
		},
		{
			delim:    plainTraversal,
			encoded:  false,
			title:    "Origin normalizes plain path traversal",
			severity: checkbase.SeverityInfo,
			detail:   "the origin collapsed a plain \"../\" dot-segment back to the resource — standard RFC 3986 behavior most caches share, so lower risk than the encoded form, but noted for mapping",
			dst:      &mapping.OriginNormalizesTraversal,
		},
	}

	for _, p := range probes {
		if *budget <= 0 {
			break
		}
		detourURL, ok := insertTraversalDetour(resource.URL, p.delim, seg)
		if !ok {
			// No final path segment to pivot on (e.g. a root "/" resource).
			continue
		}
		*budget--

		ex, err := fetchExchange(ctx, pctx, detourURL)
		if err != nil {
			continue
		}

		normalized := sameResponse(base, ex)
		*p.dst = &normalized
		if !normalized {
			continue
		}
		obs = append(obs, harnessx.Observation{
			CheckID:     checkbase.CheckIDDelimiterMapper,
			ResourceID:  resource.ID,
			Title:       p.title,
			Description: p.detail,
			Evidence:    "probed: " + detourURL,
			Metadata:    map[string]string{checkbase.SeverityKey: p.severity},
		})
	}
	return obs
}

// traversalForm is one dot-segment spelling probed for normalization: the
// delimiter spliced between the throwaway segment and the resource's final
// segment, where the origin's verdict lives, and where the cache-side verdict
// is recorded.
type traversalForm struct {
	delim   string
	encoded bool
	cache   *cdn.NormalizationOrder
}

// probeCacheNormalizationOrder answers the question probeNormalization leaves
// open: given an origin that collapses a detour path back to the resource,
// does the *cache* normalize that path before keying it (CloudFront, Azure
// Front Door, Imperva) or key the verbatim detour (Cloudflare, Google Cloud
// CDN, Fastly)? It is only worth asking for forms the origin normalizes.
//
// All requests share one cache-buster token, so the canonical entry it primes
// is private to this probe:
//
//	prime   GET <resource>?<buster> twice; the repeat must be a cache hit, or
//	        the cache isn't observably storing this resource and nothing below
//	        can be told apart from a miss.
//	R_d     GET <detour of resource>?<buster> (fresh random segment):
//	        hit  -> the cache collapsed the detour onto the primed canonical key:
//	                it normalizes BEFORE keying.
//	        miss -> repeat it; a hit now means the cache stored the origin's
//	                response under the verbatim detour key: it normalizes AFTER
//	                (or never) — the web-cache-deception condition.
//
// The measured verdict is recorded in mapping and cross-checked against the
// CDN registry's documented behavior for the detected CDN.
func probeCacheNormalizationOrder(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, base checkbase.Exchange, budget *int, mapping *cdn.TargetQuirks) []harnessx.Observation {
	var forms []traversalForm
	if o := mapping.OriginNormalizesEncodedTraversal; o != nil && *o {
		forms = append(forms, traversalForm{delim: encodedTraversal, encoded: true, cache: &mapping.CacheEncodedTraversal})
	}
	if o := mapping.OriginNormalizesTraversal; o != nil && *o {
		forms = append(forms, traversalForm{delim: plainTraversal, cache: &mapping.CacheTraversal})
	}
	if len(forms) == 0 || *budget < 3 {
		return nil
	}

	bp, err := checkbase.NewCacheBusterProbe(resource.URL, pctx)
	if err != nil {
		return nil
	}

	// Prime the canonical entry and require the repeat to be served from cache.
	var primed checkbase.Exchange
	for i := 0; i < 2; i++ {
		*budget--
		if primed, err = fetchExchangeWith(ctx, pctx, bp.URL, bp.Header); err != nil {
			return nil
		}
	}
	det := cdn.Detect(primed.Header)
	if !servedFromCache(primed) {
		return unobservedOrderObservation(resource, det.CDN, forms)
	}

	var obs []harnessx.Observation
	var unresolved []traversalForm
	for _, f := range forms {
		order, evidence := cacheNormalizationOrder(ctx, pctx, bp, f, base, budget)
		if order == cdn.NormalizationUnknown {
			unresolved = append(unresolved, f)
			continue
		}
		*f.cache = order
		obs = append(obs, cacheOrderObservation(resource, det.CDN, f, order, evidence))
	}
	return append(obs, unobservedOrderObservation(resource, det.CDN, unresolved)...)
}

// cacheNormalizationOrder runs the detour half of the probe for one form
// against an already-primed canonical entry. It returns the detour URL that
// established the verdict as evidence, and NormalizationUnknown when the budget
// ran out, the origin answered the detour inconsistently, or neither request
// was observably served from cache.
func cacheNormalizationOrder(ctx context.Context, pctx *checkbase.ProbeCtx, bp checkbase.CacheBusterProbe, f traversalForm, base checkbase.Exchange, budget *int) (cdn.NormalizationOrder, string) {
	detourURL, ok := insertTraversalDetour(bp.URL, f.delim, randomPathToken())
	if !ok {
		return cdn.NormalizationUnknown, ""
	}
	for attempt := 0; attempt < 2; attempt++ {
		if *budget <= 0 {
			break
		}
		*budget--
		ex, err := fetchExchangeWith(ctx, pctx, detourURL, bp.Header)
		if err != nil || !sameResponse(base, ex) {
			break
		}
		if servedFromCache(ex) {
			if attempt == 0 {
				return cdn.NormalizesBeforeRules, detourURL
			}
			return cdn.NormalizesAfterRules, detourURL
		}
	}
	return cdn.NormalizationUnknown, detourURL
}

// servedFromCache reports whether ex looks like it came out of a cache: a
// normalized HIT verdict, or a non-zero Age (a fresh response can carry
// "Age: 0", so zero proves nothing).
func servedFromCache(ex checkbase.Exchange) bool {
	d := cdn.Detect(ex.Header)
	return d.State == cdn.StateHit || (d.Age != nil && *d.Age > 0)
}

// cacheOrderObservation turns a measured order into a finding. A cache that
// normalizes after keying while the origin collapses the path is the exploitable
// side; a cache that normalizes first agrees with the origin and is reported for
// mapping only. The registry's documented behavior for the detected CDN is
// appended as a cross-check.
func cacheOrderObservation(resource harnessx.Resource, cdnName string, f traversalForm, order cdn.NormalizationOrder, evidenceURL string) harnessx.Observation {
	form := `plain "../"`
	if f.encoded {
		form = `encoded "..%2f"`
	}

	title := fmt.Sprintf("Cache normalizes %s traversal before applying cache rules", form)
	severity := checkbase.SeverityInfo
	detail := fmt.Sprintf("a %s detour path was answered from the cache entry primed for the canonical resource — the cache collapses the path before building its key, so it agrees with the origin and the detour cannot be used to store the response under a distinct URL", form)
	if order == cdn.NormalizesAfterRules {
		title = fmt.Sprintf("Cache keys %s traversal verbatim", form)
		severity = checkbase.SeverityMedium
		if f.encoded {
			severity = checkbase.SeverityHigh
		}
		detail = fmt.Sprintf("the origin collapses a %s detour path back to the resource, but the cache did not: the detour was a miss and a repeat was served from cache, so the cache stored the origin's response under the verbatim detour URL — it applies its rules and key before normalizing. Combined with a static-looking cache rule on the detour prefix, that is web cache deception", form)
	}

	return harnessx.Observation{
		CheckID:     checkbase.CheckIDDelimiterMapper,
		ResourceID:  resource.ID,
		Title:       title,
		Description: detail + documentedOrderNote(cdnName, order),
		Evidence:    "probed: " + evidenceURL,
		Metadata:    map[string]string{checkbase.SeverityKey: severity},
	}
}

// unobservedOrderObservation reports, for forms whose cache-side order could
// not be measured, what the detected CDN is documented to do — an Info hint,
// emitted only when a CDN was fingerprinted and has documented behavior.
func unobservedOrderObservation(resource harnessx.Resource, cdnName string, forms []traversalForm) []harnessx.Observation {
	sig, ok := cdn.ByName(cdnName)
	if !ok || sig.PathNormalization == cdn.NormalizationUnknown || len(forms) == 0 {
		return nil
	}
	return []harnessx.Observation{{
		CheckID:    checkbase.CheckIDDelimiterMapper,
		ResourceID: resource.ID,
		Title:      "Cache path-normalization order not observable",
		Description: fmt.Sprintf("the origin collapses traversal detour paths, but the cache's normalization order could not be measured (the resource was not observably served from cache). %s is documented to normalize the path %s applying its cache rules — treat that as an unverified expectation",
			sig.Name, string(sig.PathNormalization)),
		Metadata: map[string]string{checkbase.SeverityKey: checkbase.SeverityInfo},
	}}
}

// documentedOrderNote compares a measured order with the registry's documented
// one for cdnName, returning a sentence to append to a finding ("" when the CDN
// is unknown or undocumented).
func documentedOrderNote(cdnName string, measured cdn.NormalizationOrder) string {
	sig, ok := cdn.ByName(cdnName)
	if !ok || sig.PathNormalization == cdn.NormalizationUnknown {
		return ""
	}
	if sig.PathNormalization == measured {
		return fmt.Sprintf("; consistent with %s's documented behavior (normalizes %s cache rules)", sig.Name, measured)
	}
	return fmt.Sprintf("; differs from %s's documented behavior (normalizes %s cache rules) — a custom rule set or another cache tier is likely in play", sig.Name, sig.PathNormalization)
}

// insertTraversalDetour rewrites resourceURL's path from /dir/base to
// /dir/<seg>{delim}base, where delim is "/../" (plain) or "/..%2f" (encoded).
// A server that resolves the dot-segment collapses /dir/<seg>/../base back to
// /dir/base, so the detour returning the baseline response is the signal the
// origin normalizes. The raw URL is assembled by hand rather than via url.URL
// so the delimiter (notably the encoded "%2f") reaches the wire verbatim,
// matching how a real client would send it. Returns false when the path has no
// final segment to pivot on (e.g. "/").
func insertTraversalDetour(resourceURL, delim, seg string) (string, bool) {
	u, err := url.Parse(resourceURL)
	if err != nil {
		return "", false
	}
	path := u.EscapedPath()
	idx := strings.LastIndex(path, "/")
	if idx < 0 || idx == len(path)-1 {
		return "", false
	}
	dir, base := path[:idx], path[idx+1:]

	raw := u.Scheme + "://" + u.Host + dir + "/" + seg + delim + base
	if u.RawQuery != "" {
		raw += "?" + u.RawQuery
	}
	return raw, true
}

// originOf returns rawURL's scheme://host[:port], the key DiscoveredQuirks is
// recorded under.
func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}

// fetchExchange issues a plain probe request (pctx's configured
// method/headers/auth) to rawURL and returns the Exchange.
func fetchExchange(ctx context.Context, pctx *checkbase.ProbeCtx, rawURL string) (checkbase.Exchange, error) {
	return fetchExchangeWith(ctx, pctx, rawURL, nil)
}

// fetchExchangeWith is fetchExchange plus extra request headers — the
// cache-buster header when the buster mode carries one.
func fetchExchangeWith(ctx context.Context, pctx *checkbase.ProbeCtx, rawURL string, extra http.Header) (checkbase.Exchange, error) {
	req, err := checkbase.NewRequest(ctx, rawURL, pctx, extra)
	if err != nil {
		return checkbase.Exchange{}, err
	}
	return checkbase.Do(ctx, pctx, req)
}

// sameResponse reports whether two exchanges are the same response for
// path-confusion purposes: identical status code and body. Shared by the
// cache-deception and delimiter-mapper checks, which both decide "the origin
// served the undelimited resource back" the same way.
func sameResponse(a, b checkbase.Exchange) bool {
	return a.StatusCode == b.StatusCode && string(a.Body) == string(b.Body)
}

// randomPathToken returns a short random, URL-unreserved token for use as a
// nonexistent path suffix/segment — distinct enough that the origin has no
// route for it, so a plain (undelimited) append changes the response.
func randomPathToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "cdprobe0000000000"
	}
	return "cd" + hex.EncodeToString(b)
}
