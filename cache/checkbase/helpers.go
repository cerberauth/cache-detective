package checkbase

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/cerberauth/harnessx/probe"
)

// NewRequest builds an HTTP request for targetURL using pctx's configured
// method, headers, cookies, and bearer token — overridden by the
// AuthProfiles entry matching targetURL's origin, if any. extra headers
// (e.g. a check-specific cache-buster or injected header) are applied last,
// so they win over both.
func NewRequest(ctx context.Context, targetURL string, pctx *ProbeCtx, extra http.Header) (*http.Request, error) {
	method := pctx.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, err
	}

	headers, cookies, bearer := resolveCredentials(req.URL, pctx)
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for _, c := range cookies {
		// Secure/HttpOnly/SameSite are response-cookie attributes; this is
		// an outgoing request cookie the caller explicitly configured for
		// probing, so gosec's response-cookie-hardening check doesn't apply.
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) //nolint:gosec // G124: outgoing probe cookie, not a response cookie
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, vs := range extra {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return req, nil
}

// resolveCredentials returns the headers, cookies and bearer token a request
// to u carries. Layers, lowest precedence first: headers/cookies recorded
// for the matching resource (ResourceSpec.Headers/.Cookies, e.g. from a
// .har import); then the scan-wide settings, or — replacing them — the
// AuthProfiles entry for u's origin. A higher layer replaces a lower
// layer's header (by canonical name) or cookie (by name) rather than
// adding a duplicate.
func resolveCredentials(u *url.URL, pctx *ProbeCtx) (map[string][]string, []Cookie, string) {
	headers, cookies, bearer := pctx.Headers, pctx.Cookies, pctx.BearerToken
	if profile, ok := pctx.AuthProfiles[requestOrigin(u)]; ok {
		headers, cookies, bearer = profile.Headers, profile.Cookies, profile.BearerToken
	}
	spec := pctx.replay.lookup(u)
	if spec == nil {
		return headers, cookies, bearer
	}

	mergedHeaders := make(map[string][]string, len(spec.Headers)+len(headers))
	for k, vs := range spec.Headers {
		mergedHeaders[http.CanonicalHeaderKey(k)] = vs
	}
	for k, vs := range headers {
		mergedHeaders[http.CanonicalHeaderKey(k)] = vs
	}

	override := make(map[string]bool, len(cookies))
	for _, c := range cookies {
		override[c.Name] = true
	}
	mergedCookies := make([]Cookie, 0, len(spec.Cookies)+len(cookies))
	for _, c := range spec.Cookies {
		if !override[c.Name] {
			mergedCookies = append(mergedCookies, c)
		}
	}
	mergedCookies = append(mergedCookies, cookies...)

	if bearer != "" {
		delete(mergedHeaders, "Authorization")
	}
	return mergedHeaders, mergedCookies, bearer
}

// EffectiveCookies returns the cookies a request to targetURL carries (see
// resolveCredentials), for checks that vary or extend them.
func EffectiveCookies(targetURL string, pctx *ProbeCtx) []Cookie {
	u, err := url.Parse(targetURL)
	if err != nil {
		return pctx.Cookies
	}
	_, cookies, _ := resolveCredentials(u, pctx)
	return cookies
}

// requestOrigin returns u's scheme://host[:port], the key AuthProfiles is
// looked up by.
func requestOrigin(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

// IsAuthenticated reports whether the request built by NewRequest for
// targetURL carries credentials: either pctx.Authenticated (the global flag,
// forced or derived from top-level BearerToken/Cookies), a per-origin
// AuthProfiles entry with its own bearer token or cookies, or recorded
// cookies / an Authorization header replayed for the matching resource.
func IsAuthenticated(targetURL string, pctx *ProbeCtx) bool {
	if pctx.Authenticated {
		return true
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	headers, cookies, bearer := resolveCredentials(u, pctx)
	if bearer != "" || len(cookies) > 0 {
		return true
	}
	// A replayed credential header counts only when it came from a recorded
	// resource; a bare scan-wide --header stays "not authenticated" as before.
	if pctx.replay.lookup(u) != nil {
		return len(headers["Authorization"]) > 0
	}
	return false
}

// Exchange is one probe request/response pair, reduced to what checks need:
// status, headers, timing, and (when read) body. It's the cache-detective
// counterpart of harnessx.Snapshot, kept local so checks can attach
// cache-specific derived fields without reaching into harnessx internals.
type Exchange struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Duration   time.Duration
	RequestURL string
	Method     string
}

// noRedirect makes client stop at the first response instead of
// transparently following redirects — every cache-detective check needs
// the raw redirect response itself (status, headers, cacheability), not
// whatever it ultimately points to.
func noRedirect(client http.Client) *http.Client {
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client
}

// Do sends req through pctx's Probe (or http.DefaultClient if unset) and
// returns the resulting Exchange.
func Do(ctx context.Context, pctx *ProbeCtx, req *http.Request) (Exchange, error) {
	client := *http.DefaultClient
	if pctx.Probe != nil {
		client = *pctx.Probe.Client()
	}
	return doWithClient(ctx, noRedirect(client), req)
}

// DoRaw sends req through a plain, retry-free *http.Client instead of
// pctx.Probe. Probe.RoundTrip unconditionally overwrites the User-Agent
// header (by design, for consistent identification across every probe
// request), which defeats a check that specifically needs to vary
// User-Agent — e.g. varykey's cache-key-inclusion probe. Use Do for
// everything else; DoRaw is the deliberate escape hatch for that one case.
func DoRaw(ctx context.Context, pctx *ProbeCtx, req *http.Request) (Exchange, error) {
	return doWithClient(ctx, noRedirect(http.Client{Timeout: pctx.Timeout}), req)
}

func doWithClient(ctx context.Context, client *http.Client, req *http.Request) (Exchange, error) {
	resp, err := probe.DoResponse(ctx, client, req)
	if err != nil {
		return Exchange{}, err
	}
	return Exchange{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       resp.Body,
		Duration:   resp.Duration,
		RequestURL: req.URL.String(),
		Method:     req.Method,
	}, nil
}
