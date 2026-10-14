package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	Description: "Maps characters the origin treats as a path delimiter (truncating its route there) but a fronting cache keys on verbatim, plus whether the origin collapses encoded/plain dot-segment traversal — the foundation discrepancy behind both cache-key poisoning and cache deception (Doyhenard, \"Gotta cache 'em all\", Black Hat USA 2024). " +
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

	obs = append(obs, mapDelimiters(ctx, pctx, resource, base, &budget, &mapping)...)
	obs = append(obs, probeNormalization(ctx, pctx, resource, base, &budget, &mapping)...)

	// Record even an all-negative mapping: a later resource under this origin
	// (or an embedding tool) can then see the origin was probed and found
	// clean, rather than re-running the sweep.
	cdn.DiscoveredQuirks.Record(mapping)

	return harnessx.Result{Data: mapping, Observations: obs}, nil
}

// mapDelimiters runs the baseline/suffix/insert sweep across
// delimiterCandidates. It first sends R1 (a plain random suffix, no
// delimiter): if the origin serves the baseline response back even for that
// unrouteable path, it ignores trailing path junk wholesale, so a later
// R2 == R0 match can't be attributed to any specific delimiter and the sweep
// is abandoned.
func mapDelimiters(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, base checkbase.Exchange, budget *int, mapping *cdn.TargetQuirks) []harnessx.Observation {
	if *budget <= 0 {
		return nil
	}
	suffix := randomPathToken()

	*budget--
	r1, err := fetchExchange(ctx, pctx, appendPathSuffix(resource.URL, suffix))
	if err != nil {
		return nil
	}
	if sameResponse(base, r1) {
		// Origin ignores trailing path junk — the probe can't isolate a
		// delimiter's effect, so don't guess.
		return nil
	}

	var obs []harnessx.Observation
	for _, d := range delimiterCandidates {
		if *budget <= 0 {
			break
		}
		*budget--

		r2URL := appendPathSuffix(resource.URL, d+suffix)
		r2, err := fetchExchange(ctx, pctx, r2URL)
		if err != nil {
			continue
		}
		if !sameResponse(base, r2) {
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
	return obs
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
			delim:    "/..%2f",
			encoded:  true,
			title:    "Origin normalizes encoded path traversal",
			severity: checkbase.SeverityHigh,
			detail:   "the origin decoded and collapsed an encoded %2f dot-segment back to the resource — a cache that keys on the verbatim (un-normalized) request path, as Cloudflare/Google Cloud/Fastly do by default, would store the origin's response under the distinct detour URL (web cache deception); caches that normalize before applying cache rules, like CloudFront/Azure/Imperva, are not affected",
			dst:      &mapping.OriginNormalizesEncodedTraversal,
		},
		{
			delim:    "/../",
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
	req, err := checkbase.NewRequest(ctx, rawURL, pctx, nil)
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
