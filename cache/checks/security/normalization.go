package security

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// --- Static-directory / nested-encoding cache deception (§5) ---------------

var NormalizationDeceptionDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDNormalizationDeception),
	Name:        "Static-Directory Path-Traversal Cache Deception",
	Description: "Requests the resource through a traversal path that starts under a static directory (/static/x/../../account, and its percent-encoded and double-encoded forms) and checks whether the origin still serves the resource and the response then gets cached. A cache that applies its \"static directory\" rule to the raw path — or decodes it fewer times than the origin — stores the origin's dynamic response under a URL anyone can request (Doyhenard, \"Gotta cache 'em all\", Black Hat USA 2024).",
	Tags:        []string{securityTag, cacheDeceptionTag, cacheKeyTag},
	// Same ordering rationale as EntanglementDef: joins at the tail of the §5
	// chain, alongside varykey and delimiter-mapper.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDCPDoS)},
	CVSSVector: cvssDeception,
	CVSSScore:  8.1,
	CWEID:      cweCacheDeception,
	OWASP:      owaspAccessControl,
}

var NormalizationDeceptionCheck = checkdef.NewResourceCheck(NormalizationDeceptionDef, runNormalizationDeception)

// staticDirPrefixes are the directory names CDNs most commonly ship a
// "cache everything under here" rule for. Ordered by prevalence so a small
// request budget still covers the likeliest ones.
var staticDirPrefixes = []string{"/static", "/assets", "/public", "/images", "/css", "/js", "/media"}

// traversalVariant is one way of writing the "go up two levels" step between
// a static-directory prefix and the real path.
type traversalVariant struct {
	name  string
	title string
	// up joins the throwaway segment to the real path. The segment is the
	// only thing the traversal pops besides the prefix, so up always climbs
	// exactly two levels.
	up string
	// detail is appended to the finding description.
	detail string
}

var traversalVariants = []traversalVariant{
	{
		name:   "plain",
		title:  "Cache deception via static-directory path traversal",
		up:     "/../../",
		detail: "the origin resolves the \"../\" segments and routes the request to the real resource, while a cache whose static-directory rule matches the raw path still sees a \"/static/...\" URL",
	},
	{
		name:   "encoded",
		title:  "Cache deception via encoded static-directory path traversal",
		up:     "/..%2f..%2f",
		detail: "the origin decodes the %2f separators and resolves the traversal to the real resource, while a cache that matches its static-directory rule before decoding sees a plain \"/static/...\" URL",
	},
	{
		name:   "nested-encoded",
		title:  "Cache deception via nested-encoded static-directory path traversal",
		up:     "/..%252f..%252f",
		detail: "the origin keeps decoding until the %252f separators become real path separators and resolves the traversal, while a cache that decodes only once still sees an opaque, static-looking \"/static/...\" URL",
	},
}

func runNormalizationDeception(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)
	budget := pctx.MaxAggressiveRequests
	if budget < 3 {
		return harnessx.Result{}, nil
	}

	u, err := url.Parse(resource.URL)
	if err != nil {
		return harnessx.Result{}, err
	}
	path := strings.TrimPrefix(u.EscapedPath(), "/")

	// R0: the canonical response every traversal variant is compared to. A
	// non-2xx baseline has nothing worth deceiving a cache into storing.
	budget--
	base, err := fetchExchange(ctx, pctx, resource.URL)
	if err != nil || base.StatusCode/100 != 2 {
		return harnessx.Result{}, nil
	}
	// A resource that is already a cache HIT is public by construction —
	// caching one more URL for it exposes nothing new.
	if cdn.Detect(base.Header).State == cdn.StateHit {
		return harnessx.Result{}, nil
	}

	// Control: the same detour *without* any traversal. If the origin serves
	// the resource for that too, it routes loosely (catch-all, or ignores the
	// directory prefix), and a match on the traversal variants below can't be
	// attributed to path normalization.
	seg := randomPathToken()
	budget--
	control, err := fetchExchange(ctx, pctx, traversalURL(u, staticDirPrefixes[0], seg, "/", path))
	if err != nil || sameResponse(base, control) {
		return harnessx.Result{}, nil
	}

	var obs []harnessx.Observation
	found := map[string]bool{}
	for _, prefix := range staticDirPrefixes {
		for _, v := range traversalVariants {
			if budget <= 0 {
				return harnessx.Result{Observations: obs}, nil
			}
			if found[v.name] {
				continue
			}
			budget--

			detourURL := traversalURL(u, prefix, seg, v.up, path)
			ex, err := fetchExchange(ctx, pctx, detourURL)
			if err != nil || !sameResponse(base, ex) || !cacheableResponse(ex.Method, ex.StatusCode, ex.Header) {
				continue
			}
			found[v.name] = true

			// The detour matching the canonical response only shows the origin
			// normalizes. Whether the *cache* stored it is a second request:
			// a HIT here, on a resource whose canonical URL is not cached, is
			// the deception working.
			severity := checkbase.SeverityMedium
			cacheNote := "the response is cacheable by its headers, but no cache HIT was observed on a repeat request, so confirm the fronting cache actually stores it"
			if budget > 0 {
				budget--
				if repeat, err := fetchExchange(ctx, pctx, detourURL); err == nil && cdn.Detect(repeat.Header).State == cdn.StateHit {
					severity = checkbase.SeverityHigh
					cacheNote = "and a repeat request was served from cache (HIT) while the canonical URL is not cached — a live cache-deception surface if the resource carries sensitive/authenticated content"
				}
			}
			obs = append(obs, harnessx.Observation{
				CheckID:     checkbase.CheckIDNormalizationDeception,
				ResourceID:  resource.ID,
				Title:       v.title,
				Description: fmt.Sprintf("requesting the resource through %q returned the canonical response: %s; %s", prefix, v.detail, cacheNote),
				Evidence:    "probed: " + detourURL,
				Metadata:    map[string]string{checkbase.SeverityKey: severity},
			})
		}
	}
	return harnessx.Result{Observations: obs}, nil
}

// traversalURL builds <origin><prefix>/<seg><up><path>[?query] by hand, so
// the percent-encoded separators in up reach the wire verbatim instead of
// being decoded and re-encoded by url.URL. path is the resource's escaped
// path without its leading "/".
func traversalURL(u *url.URL, prefix, seg, up, path string) string {
	raw := u.Scheme + "://" + u.Host + prefix + "/" + seg + up + path
	if u.RawQuery != "" {
		raw += "?" + u.RawQuery
	}
	return raw
}
