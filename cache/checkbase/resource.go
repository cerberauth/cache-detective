package checkbase

import (
	"net/http"
	"net/url"
	"slices"

	"github.com/cerberauth/harnessx"
)

// ResourceRequest is the request shape of one resource, for a host engine
// that supplies its own resources: set it as harnessx.Resource.Data. Every
// field is optional and, when set, wins over the matching scan-wide
// ProbeCtx value for probes of that resource (including the cache-buster and
// path-confusion variants checks derive from its URL).
type ResourceRequest struct {
	// Method replaces ProbeCtx.Method. harnessx.Resource.Method is used when
	// it is empty.
	Method string

	// Headers and Cookies are merged over the scan-wide (or per-origin
	// AuthProfiles) ones: a header (by canonical name) or cookie (by name)
	// set here replaces the scan-wide one.
	Headers map[string][]string
	Cookies []Cookie

	// Body is sent with every probe of the resource.
	Body []byte
}

// resourceRequest returns the ResourceRequest a resource carries and whether
// it overrides anything.
func resourceRequest(res harnessx.Resource) (ResourceRequest, bool) {
	var rr ResourceRequest
	switch d := res.Data.(type) {
	case ResourceRequest:
		rr = d
	case *ResourceRequest:
		if d != nil {
			rr = *d
		}
	}
	if rr.Method == "" {
		rr.Method = res.Method
	}
	return rr, rr.Method != "" || len(rr.Headers) > 0 || len(rr.Cookies) > 0 || rr.Body != nil
}

// ForResource returns the ProbeCtx a check probing res uses: pctx with the
// resource's own method, headers, cookies and body (see ResourceRequest)
// layered over the scan-wide values. It returns pctx itself when res
// overrides nothing, and never mutates pctx, so it is safe to call from
// concurrent per-resource checks.
func ForResource(pctx *ProbeCtx, res harnessx.Resource) *ProbeCtx {
	rr, ok := resourceRequest(res)
	if !ok {
		return pctx
	}
	out := *pctx
	if rr.Method != "" {
		out.Method = rr.Method
	}
	if rr.Body != nil {
		out.Body = rr.Body
	}
	if len(rr.Headers) == 0 && len(rr.Cookies) == 0 {
		return &out
	}

	u, err := url.Parse(res.URL)
	if err != nil {
		return &out
	}
	// Start from the credentials the resource would carry anyway (scan-wide,
	// or its origin's AuthProfile) and layer the resource's own on top.
	headers, cookies, bearer := pctx.Headers, pctx.Cookies, pctx.BearerToken
	origin := requestOrigin(u)
	if profile, ok := pctx.AuthProfiles[origin]; ok {
		headers, cookies, bearer = profile.Headers, profile.Cookies, profile.BearerToken
	}
	merged := make(map[string][]string, len(headers)+len(rr.Headers))
	for k, vs := range headers {
		merged[http.CanonicalHeaderKey(k)] = vs
	}
	ownAuth := false
	for k, vs := range rr.Headers {
		k = http.CanonicalHeaderKey(k)
		merged[k] = vs
		ownAuth = ownAuth || (k == "Authorization" && len(vs) > 0)
	}
	if ownAuth {
		// The resource's own Authorization header outranks a scan-wide bearer token.
		bearer = ""
	}
	override := make(map[string]bool, len(rr.Cookies))
	for _, c := range rr.Cookies {
		override[c.Name] = true
	}
	mergedCookies := make([]Cookie, 0, len(cookies)+len(rr.Cookies))
	for _, c := range cookies {
		if !override[c.Name] {
			mergedCookies = append(mergedCookies, c)
		}
	}
	mergedCookies = append(mergedCookies, rr.Cookies...)

	profiles := make(map[string]AuthProfile, len(pctx.AuthProfiles)+1)
	for k, v := range pctx.AuthProfiles {
		profiles[k] = v
	}
	profiles[origin] = AuthProfile{Headers: merged, Cookies: slices.Clip(mergedCookies), BearerToken: bearer}
	out.AuthProfiles = profiles
	if len(rr.Cookies) > 0 || ownAuth {
		out.Authenticated = true
	}
	return &out
}
