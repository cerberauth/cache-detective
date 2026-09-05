// Package security implements §5 of cache-detective: cache poisoning and
// cache deception probing. Every check here is opt-in — gated behind
// ProbeCtx.Aggressive — since a positive result means the check just
// demonstrated it can plant content in a shared cache other users may be
// served. Even with Aggressive set, ProbeCtx.MaxAggressiveRequests hard-caps
// how many extra requests any one check issues per resource.
package security

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// securityTag is applied to every CheckDef in this package.
const securityTag = "security"

// aggressiveGate reports whether a security check should actually run.
// Deliberately not wired as a harnessx.SkipDecision (checkdef.WithSkip):
// harnessreport turns *every* check-level skip into a reportx Finding
// (using the check's Name/CVSS as if it were an inert placeholder), with
// no way to tell "explicitly gated off by design" apart from "found
// nothing" or "genuinely vulnerable" in the JSON output. Since these four
// checks are gated off on every default (non-aggressive) scan, wiring
// them through Skip would put four misleading entries in every report.
// Checking the gate inside Run instead, and returning a plain empty
// Result, avoids that: harnessreport only emits a Finding for a Result
// that carries Observations or Data, so "gated off" produces no report
// entry at all. See the README's "Known limitations" section.
func aggressiveGate(target harnessx.Target) bool {
	pctx, ok := target.Data.(*checkbase.ProbeCtx)
	return ok && pctx.Aggressive
}

// --- Unkeyed header injection (§5) -----------------------------------------

var UnkeyedHeaderDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDUnkeyedHeader),
	Name:        "Unkeyed Header Injection",
	Description: "Injects a marker via a header commonly left unkeyed by CDNs (e.g. X-Forwarded-Host) and checks whether a follow-up plain request receives the poisoned response — classic web cache poisoning.",
	Tags:        []string{securityTag, "cache-poisoning"},
	DependsOn:   []string{string(checkbase.CheckIDDiscovery)},
	CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
	CVSSScore:   9.3,
	CWEID:       "CWE-444",
	OWASP:       "A05:2021-Security Misconfiguration",
}

var UnkeyedHeaderCheck = checkdef.NewResourceCheck(UnkeyedHeaderDef, runUnkeyedHeader)

// unkeyedHeaderCandidates are headers frequently reflected into a response
// (redirects, canonical links, asset URLs) without being part of the cache
// key — the textbook web-cache-poisoning unkeyed-input surface.
var unkeyedHeaderCandidates = []string{"X-Forwarded-Host", "X-Forwarded-Scheme", "X-Original-URL", "X-Rewrite-URL"}

func runUnkeyedHeader(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)
	marker := "cache-detective-poison-marker.invalid"

	budget := pctx.MaxAggressiveRequests
	var obs []harnessx.Observation

	for _, header := range unkeyedHeaderCandidates {
		if budget < 2 {
			break
		}
		budget -= 2

		poisonReq, err := checkbase.NewRequest(ctx, resource.URL, pctx, http.Header{header: {marker}})
		if err != nil {
			continue
		}
		poisoned, err := checkbase.Do(ctx, pctx, poisonReq)
		if err != nil {
			continue
		}
		if !strings.Contains(string(poisoned.Body), marker) && !containsHeaderValue(poisoned.Header, marker) {
			// The marker wasn't even reflected into this response — no
			// injection surface via this header, skip the confirmation
			// request.
			continue
		}

		confirmReq, err := checkbase.NewRequest(ctx, resource.URL, pctx, nil)
		if err != nil {
			continue
		}
		confirm, err := checkbase.Do(ctx, pctx, confirmReq)
		if err != nil {
			continue
		}

		if strings.Contains(string(confirm.Body), marker) || containsHeaderValue(confirm.Header, marker) {
			obs = append(obs, harnessx.Observation{
				CheckID:     checkbase.CheckIDUnkeyedHeader,
				ResourceID:  resource.ID,
				Title:       fmt.Sprintf("Unkeyed header injection via %s", header),
				Description: fmt.Sprintf("a marker injected via the %s request header was reflected into the response and then served, unmodified, to a follow-up plain request — the header is not part of the cache key", header),
				Evidence:    fmt.Sprintf("injected %s: %s", header, marker),
				Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityCritical},
			})
		}
	}

	return harnessx.Result{Observations: obs}, nil
}

func containsHeaderValue(h http.Header, marker string) bool {
	for _, vs := range h {
		for _, v := range vs {
			if strings.Contains(v, marker) {
				return true
			}
		}
	}
	return false
}

// --- Cache deception (§5) --------------------------------------------------

var CacheDeceptionDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDCacheDeception),
	Name:        "Cache Deception",
	Description: "Appends a static-file extension / nonexistent sub-path to the resource path and checks whether the (potentially authenticated) origin response gets cached under that URL.",
	Tags:        []string{securityTag, "cache-deception"},
	DependsOn:   []string{string(checkbase.CheckIDDiscovery)},
	CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
	CVSSScore:   8.1,
	CWEID:       "CWE-524",
	OWASP:       "A01:2021-Broken Access Control",
}

var CacheDeceptionCheck = checkdef.NewResourceCheck(CacheDeceptionDef, runCacheDeception)

// deceptionSuffixes are path-confusion suffixes known to be cached by
// default on many CDN configs (static-asset extensions, or a nonexistent
// path segment appended after the real one).
var deceptionSuffixes = []string{"/nonexistent.js", "/nonexistent.css", ".js", ".css", "/nonexistent.jpg"}

func runCacheDeception(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)

	baseReq, err := checkbase.NewRequest(ctx, resource.URL, pctx, nil)
	if err != nil {
		return harnessx.Result{}, err
	}
	base, err := checkbase.Do(ctx, pctx, baseReq)
	if err != nil {
		return harnessx.Result{}, err
	}

	budget := pctx.MaxAggressiveRequests
	var obs []harnessx.Observation
	for _, suffix := range deceptionSuffixes {
		if budget <= 0 {
			break
		}
		budget--

		deceptiveURL := strings.TrimRight(resource.URL, "/") + suffix
		req, err := checkbase.NewRequest(ctx, deceptiveURL, pctx, nil)
		if err != nil {
			continue
		}
		ex, err := checkbase.Do(ctx, pctx, req)
		if err != nil {
			continue
		}

		if ex.StatusCode == base.StatusCode && string(ex.Body) == string(base.Body) && cacheableResponse(ex.Header) {
			obs = append(obs, harnessx.Observation{
				CheckID:     checkbase.CheckIDCacheDeception,
				ResourceID:  resource.ID,
				Title:       "Cache deception via path confusion",
				Description: fmt.Sprintf("appending %q to the resource path still served the original (identical) response body, and that response looks cacheable — a static-extension/path-confusion cache-deception surface if the original response carried sensitive/authenticated content", suffix),
				Evidence:    "probed: " + deceptiveURL,
				Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityHigh},
			})
		}
	}

	return harnessx.Result{Observations: obs}, nil
}

func cacheableResponse(h http.Header) bool {
	cc := strings.ToLower(h.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") {
		return false
	}
	return strings.Contains(cc, "public") || strings.Contains(cc, "max-age") || h.Get("Expires") != ""
}

// --- Error-response caching (§5) -------------------------------------------

var ErrorCachingDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDErrorCaching),
	Name:        "Error Response Caching",
	Description: "Requests a resource with a deliberately invalid Accept/cache-buster to provoke a 4xx/5xx and checks whether the error response itself is cached longer than intended.",
	Tags:        []string{securityTag, "error-caching"},
	DependsOn:   []string{string(checkbase.CheckIDDiscovery)},
	CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
	CVSSScore:   5.3,
	CWEID:       "CWE-524",
}

var ErrorCachingCheck = checkdef.NewResourceCheck(ErrorCachingDef, runErrorCaching)

func runErrorCaching(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)

	req, err := checkbase.NewRequest(ctx, resource.URL, pctx, http.Header{"Range": {"bytes=999999999-"}})
	if err != nil {
		return harnessx.Result{}, err
	}
	ex, err := checkbase.Do(ctx, pctx, req)
	if err != nil {
		return harnessx.Result{}, err
	}

	if ex.StatusCode < 400 {
		return harnessx.Result{}, nil
	}

	cc := strings.ToLower(ex.Header.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") {
		return harnessx.Result{}, nil
	}
	if !strings.Contains(cc, "max-age") && ex.Header.Get("Expires") == "" {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Observations: []harnessx.Observation{{
		CheckID:     checkbase.CheckIDErrorCaching,
		ResourceID:  resource.ID,
		Title:       "Error response is cacheable",
		Description: fmt.Sprintf("a %d error response carries cache-control directives that make it cacheable — a transient error could be served to other users for the declared TTL", ex.StatusCode),
		Evidence:    fmt.Sprintf("status=%d cache-control=%q", ex.StatusCode, ex.Header.Get("Cache-Control")),
		Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityMedium},
	}}}, nil
}

// --- Response splitting via cache-key manipulation (§5) --------------------

var ResponseSplittingDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDResponseSplitting),
	Name:        "Response Splitting via Cache-Key Manipulation",
	Description: "Injects a CRLF-encoded header/path fragment into an unkeyed input and checks whether it's reflected as literal injected headers in the (potentially cached) response — HTTP response splitting exploitable through the cache.",
	Tags:        []string{securityTag, "cache-poisoning", "response-splitting"},
	// Depends on UnkeyedHeaderCheck, not just discovery: both checks poison
	// the same unkeyed inputs (X-Forwarded-Host among them) on the same
	// resource, and harnessx runs same-level checks concurrently — without
	// this ordering, one check's poison request can land between the
	// other's poison/confirm pair and mask its finding. Every §5 check that
	// manipulates the same unkeyed input on a live target needs this same
	// care; it isn't unique to cache-detective's test suite.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDUnkeyedHeader)},
	CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
	CVSSScore:  9.3,
	CWEID:      "CWE-113",
}

var ResponseSplittingCheck = checkdef.NewResourceCheck(ResponseSplittingDef, runResponseSplitting)

func runResponseSplitting(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)
	const injectedHeaderName = "X-Cache-Detective-Injected"
	// Go's net/http rejects raw CR/LF in header values before they ever hit
	// the wire (net/http.Header.Write / textproto validate this), so the
	// payload is sent URL-encoded — the way it would reach a vulnerable
	// origin that itself decodes and reflects the value into a raw header
	// write. A defended origin either rejects/sanitizes it or reflects it
	// verbatim (still encoded); only a real split shows up as a second,
	// literal header in the parsed response, which is what's checked for.
	payload := "x%0d%0a" + injectedHeaderName + ":%20injected"

	req, err := checkbase.NewRequest(ctx, resource.URL+withMarkerQuery(resource.URL, payload), pctx, http.Header{
		"X-Forwarded-Host": {payload},
	})
	if err != nil {
		return harnessx.Result{}, err
	}
	ex, err := checkbase.Do(ctx, pctx, req)
	if err != nil {
		return harnessx.Result{}, err
	}

	if ex.Header.Get(injectedHeaderName) != "" {
		return harnessx.Result{Observations: []harnessx.Observation{{
			CheckID:     checkbase.CheckIDResponseSplitting,
			ResourceID:  resource.ID,
			Title:       "Response splitting via unkeyed input",
			Description: "a CRLF-encoded payload placed in an unkeyed header was reflected as a literal, separate response header — if this response is cacheable, an attacker-controlled header can be planted into the shared cache",
			Evidence:    "injected header observed: " + injectedHeaderName,
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityCritical},
		}}}, nil
	}
	return harnessx.Result{}, nil
}

func withMarkerQuery(resourceURL, payload string) string {
	sep := "?"
	if strings.Contains(resourceURL, "?") {
		sep = "&"
	}
	return sep + "cd_probe=" + payload
}
