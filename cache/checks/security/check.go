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
	"net/url"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
)

// securityTag is applied to every CheckDef in this package.
const securityTag = "security"

// cachePoisoningTag is applied to every CheckDef here that can plant
// attacker-controlled content into a shared cache (as opposed to
// cache-deception, which exfiltrates rather than plants).
const cachePoisoningTag = "cache-poisoning"

// aggressiveGate reports whether a security check should actually run.
// Deliberately not wired as a harnessx.SkipDecision (checkdef.WithSkip):
// harnessreport turns *every* check-level skip into a reportx Finding
// (using the check's Name/CVSS as if it were an inert placeholder), with
// no way to tell "explicitly gated off by design" apart from "found
// nothing" or "genuinely vulnerable" in the JSON output. Since these five
// checks are gated off on every default (non-aggressive) scan, wiring
// them through Skip would put five misleading entries in every report.
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
	Tags:        []string{securityTag, cachePoisoningTag},
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
	// DependsOn UnkeyedHeaderCheck, not just Discovery: both checks issue a
	// plain baseline GET at the same resource, and harnessx runs same-level
	// checks concurrently. Against a single-slot demo cache, this check's
	// own baseline request landing between UnkeyedHeaderCheck's poison and
	// confirm requests would silently overwrite the poisoned entry with a
	// clean one, masking that finding. See ResponseSplittingDef below for
	// the same reasoning.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDUnkeyedHeader)},
	CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
	CVSSScore:  8.1,
	CWEID:      "CWE-524",
	OWASP:      "A01:2021-Broken Access Control",
}

var CacheDeceptionCheck = checkdef.NewResourceCheck(CacheDeceptionDef, runCacheDeception)

// deceptionDelimiters are characters research (PortSwigger's "Gotta cache
// 'em all", 2024; the earlier "Cached and Confused" paper) has found
// shared caches use to mark the end of the "meaningful" path — deciding
// cacheability from whatever static-looking suffix follows — while the
// origin keeps routing on the full, undelimited path. Tried ahead of the
// plain-suffix sweep below since they're cheap (few combinations) and
// probe a distinct mechanism from a bare static extension.
var deceptionDelimiters = []string{";", "%00", "%0a", "$"}

// deceptionSuffixes are path-confusion suffixes known to be cached by
// default on many CDN configs: delimiter+static-extension combinations
// (see deceptionDelimiters), a nonexistent path segment appended after the
// real one, plus every static-asset extension any CDN in the registry
// (cache/cdn) caches by default — see Signature.StaticExtensions — both as
// a bare suffix (".js") and as a nonexistent sub-path ("/nonexistent.js").
var deceptionSuffixes = buildDeceptionSuffixes()

func buildDeceptionSuffixes() []string {
	exts := cdn.AllStaticExtensions()
	suffixes := make([]string, 0, len(deceptionDelimiters)*2+len(exts)*2)
	for _, d := range deceptionDelimiters {
		suffixes = append(suffixes, d+".css", d+".js")
	}
	for _, ext := range exts {
		suffixes = append(suffixes, ext, "/nonexistent"+ext)
	}
	return suffixes
}

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

		deceptiveURL := appendPathSuffix(resource.URL, suffix)
		req, err := checkbase.NewRequest(ctx, deceptiveURL, pctx, nil)
		if err != nil {
			continue
		}
		ex, err := checkbase.Do(ctx, pctx, req)
		if err != nil {
			continue
		}

		if ex.StatusCode == base.StatusCode && string(ex.Body) == string(base.Body) && cacheableResponse(ex.Method, ex.StatusCode, ex.Header) {
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

// cacheableResponse defers to the same RFC 9111 analysis the cacheability
// check (§1) uses, rather than a header-substring heuristic: a response with
// no Cache-Control at all is still cacheable by default status/method
// semantics (e.g. a bare 200 GET), which is exactly the case a static-file
// path-confusion deception exploits — the deceptive path never sets its own
// Cache-Control, it just rides the origin's default cacheability.
// appendPathSuffix appends suffix to resourceURL's path, leaving any
// existing query string untouched — rather than blindly concatenating onto
// the end of the whole URL, which would land a suffix like ";.css" or
// "%00.css" inside an existing query value instead of the path, corrupting
// it (and, for a literal "%00", turning a path-confusion probe into an
// unrelated live meta-character injection against the origin's query
// handling). suffix is inserted as raw text, not re-escaped, so delimiter
// suffixes carrying a literal "%00"/"%0a" reach the wire as those three/four
// characters, not a decoded byte — matching how a real client sends them.
func appendPathSuffix(resourceURL, suffix string) string {
	base, query, hasQuery := strings.Cut(resourceURL, "?")
	base = strings.TrimRight(base, "/") + suffix
	if hasQuery {
		return base + "?" + query
	}
	return base
}

func cacheableResponse(method string, statusCode int, h http.Header) bool {
	return cacheability.Analyze(method, statusCode, h, false).Cacheable
}

// --- Error-response caching (§5) -------------------------------------------

var ErrorCachingDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDErrorCaching),
	Name:        "Error Response Caching",
	Description: "Requests a resource with a deliberately invalid Accept/cache-buster to provoke a 4xx/5xx and checks whether the error response itself is cached longer than intended.",
	Tags:        []string{securityTag, "error-caching"},
	// DependsOn CacheDeceptionCheck (and transitively UnkeyedHeaderCheck),
	// not just Discovery — same same-level-race reasoning as
	// CacheDeceptionDef above: this check's own request to the resource
	// could otherwise land between another security check's poison/confirm
	// pair and mask its finding.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDCacheDeception)},
	CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
	CVSSScore:  5.3,
	CWEID:      "CWE-524",
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
	Tags:        []string{securityTag, cachePoisoningTag, "response-splitting"},
	// Depends on ErrorCachingCheck (and transitively CacheDeceptionCheck,
	// UnkeyedHeaderCheck), not just discovery: every §5 check probes or
	// poisons the same resource, and harnessx runs same-level checks
	// concurrently — without a full chain of ordering, one check's request
	// can land between another's poison/confirm pair and mask its finding.
	// This DependsOn chain (UnkeyedHeader -> CacheDeception -> ErrorCaching
	// -> ResponseSplitting) runs every §5 check strictly one at a time
	// against a given resource; it isn't unique to cache-detective's test
	// suite.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDErrorCaching)},
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

// --- Cache-Poisoned Denial of Service / CPDoS (§5) --------------------------

var CPDoSDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDCPDoS),
	Name:        "Cache-Poisoned Denial of Service (CPDoS)",
	Description: "Provokes an origin error via an oversized header block, an HTTP meta-character in an existing query value, or a method-override header, then checks whether a follow-up plain request is served the same error back — the three variants (HHO/HMC/HMO) from the original 2019 CPDoS disclosure (see cdn.Registry's cpdos-2019 Quirk).",
	Tags:        []string{securityTag, cachePoisoningTag, "cpdos", "denial-of-service"},
	// DependsOn ResponseSplittingCheck, the previous tail of the §5
	// ordering chain (UnkeyedHeader -> CacheDeception -> ErrorCaching ->
	// ResponseSplitting), making this check the new tail — see
	// cacheability.Def/varykey.Def, which now depend on CPDoSCheck
	// instead. Same same-level-race reasoning as the others: every §5
	// check probes or poisons the same resource, and harnessx runs
	// same-level checks concurrently.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDResponseSplitting)},
	CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
	CVSSScore:  7.5,
	CWEID:      "CWE-444",
}

var CPDoSCheck = checkdef.NewResourceCheck(CPDoSDef, runCPDoS)

// cpdosHeaderPadding is sized to sit between a typical origin's own header
// block limit (e.g. Apache/nginx's ~8KB default) and a typical CDN's more
// generous one (e.g. CloudFront's 20KB) — large enough to trip an origin
// limit while still being small enough that most fronting caches forward
// it untouched.
var cpdosHeaderPadding = strings.Repeat("A", 12000)

// cpdosMetaCharacters are control characters a CDN commonly forwards
// after percent-decoding a query value, but that stricter origin input
// validation rejects outright.
var cpdosMetaCharacters = []string{"\x00", "\r", "\n"}

func runCPDoS(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)
	budget := pctx.MaxAggressiveRequests

	var obs []harnessx.Observation
	probes := []func(context.Context, *checkbase.ProbeCtx, harnessx.Resource) (harnessx.Observation, bool){
		probeCPDoSHeaderOversize,
		probeCPDoSMethodOverride,
		probeCPDoSMetaCharacter,
	}
	for _, probe := range probes {
		if budget < 2 {
			break
		}
		budget -= 2
		ob, found := probe(ctx, pctx, resource)
		if !found {
			continue
		}
		obs = append(obs, ob)
		// A confirmed poisoning leaves the (typically single-slot, in these
		// simulated caches) resource stuck serving the error it just
		// planted — running the remaining variants against it now would
		// just observe that same residual poisoning and misattribute it to
		// a mechanism that didn't actually cause it. One confirmed finding
		// per resource is enough to flag it as CPDoS-vulnerable.
		break
	}

	return harnessx.Result{Observations: obs}, nil
}

// cpdosConfirm reissues a plain, unmodified GET against resource.URL after
// a poisoning probe and reports whether the same error status came back —
// i.e. whether the provoked error was cached and is now being replayed to
// ordinary callers, rather than being a one-off response to the probe
// itself.
func cpdosConfirm(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, poisonedStatus int) bool {
	confirmReq, err := checkbase.NewRequest(ctx, resource.URL, pctx, nil)
	if err != nil {
		return false
	}
	confirm, err := checkbase.Do(ctx, pctx, confirmReq)
	if err != nil {
		return false
	}
	return confirm.StatusCode == poisonedStatus
}

// probeCPDoSHeaderOversize implements CPDoS's "HTTP Header Oversize" (HHO)
// variant: a header block a fronting cache accepts but the origin doesn't.
func probeCPDoSHeaderOversize(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource) (harnessx.Observation, bool) {
	poisonReq, err := checkbase.NewRequest(ctx, resource.URL, pctx, http.Header{"X-Cache-Detective-Padding": {cpdosHeaderPadding}})
	if err != nil {
		return harnessx.Observation{}, false
	}
	poisoned, err := checkbase.Do(ctx, pctx, poisonReq)
	if err != nil || poisoned.StatusCode < 400 {
		return harnessx.Observation{}, false
	}

	if !cpdosConfirm(ctx, pctx, resource, poisoned.StatusCode) {
		return harnessx.Observation{}, false
	}
	return harnessx.Observation{
		CheckID:     checkbase.CheckIDCPDoS,
		ResourceID:  resource.ID,
		Title:       "CPDoS via oversized headers (HHO)",
		Description: fmt.Sprintf("an oversized header block provoked a %d origin error, and a follow-up plain request without that header received the same error — a shared cache accepting a larger header block than the origin is caching and replaying that error to every caller", poisoned.StatusCode),
		Evidence:    fmt.Sprintf("status=%d after an oversized header, then again on an unmodified follow-up request", poisoned.StatusCode),
		Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityHigh},
	}, true
}

// probeCPDoSMethodOverride implements CPDoS's "HTTP Method Override" (HMO)
// variant: a header letting the origin re-interpret a GET as another
// method, invisibly to the cache which keys purely on the real method/line.
func probeCPDoSMethodOverride(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource) (harnessx.Observation, bool) {
	poisonReq, err := checkbase.NewRequest(ctx, resource.URL, pctx, http.Header{"X-HTTP-Method-Override": {"DELETE"}})
	if err != nil {
		return harnessx.Observation{}, false
	}
	poisoned, err := checkbase.Do(ctx, pctx, poisonReq)
	if err != nil || poisoned.StatusCode < 400 {
		return harnessx.Observation{}, false
	}

	if !cpdosConfirm(ctx, pctx, resource, poisoned.StatusCode) {
		return harnessx.Observation{}, false
	}
	return harnessx.Observation{
		CheckID:     checkbase.CheckIDCPDoS,
		ResourceID:  resource.ID,
		Title:       "CPDoS via method override (HMO)",
		Description: fmt.Sprintf("a GET carrying X-HTTP-Method-Override honored by the origin provoked a %d error, and a follow-up plain GET received the same error — the cache keyed on the real GET method/line, unaware the override header changed how the origin handled it", poisoned.StatusCode),
		Evidence:    fmt.Sprintf("status=%d after X-HTTP-Method-Override: DELETE, then again on an unmodified follow-up GET", poisoned.StatusCode),
		Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityHigh},
	}, true
}

// probeCPDoSMetaCharacter implements CPDoS's "HTTP Meta Character" (HMC)
// variant: a control character in an existing query value the origin
// rejects, while the cache keys on the path alone. Needs an existing query
// parameter to mutate — a resource with no query string has no surface for
// this variant, and is silently skipped.
func probeCPDoSMetaCharacter(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource) (harnessx.Observation, bool) {
	u, err := url.Parse(resource.URL)
	if err != nil || u.RawQuery == "" {
		return harnessx.Observation{}, false
	}
	q := u.Query()
	var param string
	for k := range q {
		param = k
		break
	}
	if param == "" {
		return harnessx.Observation{}, false
	}

	poisonedURL := *u
	pq := poisonedURL.Query()
	pq.Set(param, pq.Get(param)+cpdosMetaCharacters[0])
	poisonedURL.RawQuery = pq.Encode()

	poisonReq, err := checkbase.NewRequest(ctx, poisonedURL.String(), pctx, nil)
	if err != nil {
		return harnessx.Observation{}, false
	}
	poisoned, err := checkbase.Do(ctx, pctx, poisonReq)
	if err != nil || poisoned.StatusCode < 400 {
		return harnessx.Observation{}, false
	}

	if !cpdosConfirm(ctx, pctx, resource, poisoned.StatusCode) {
		return harnessx.Observation{}, false
	}
	return harnessx.Observation{
		CheckID:     checkbase.CheckIDCPDoS,
		ResourceID:  resource.ID,
		Title:       "CPDoS via HTTP meta-character (HMC)",
		Description: fmt.Sprintf("a control character injected into the existing %q query value provoked a %d origin error, and a follow-up plain request (path unchanged) received the same error — the cache keyed on the path alone, unaware of the query value that caused it", param, poisoned.StatusCode),
		Evidence:    fmt.Sprintf("status=%d after a meta-character in %q, then again on an unmodified follow-up request", poisoned.StatusCode, param),
		Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityHigh},
	}, true
}
