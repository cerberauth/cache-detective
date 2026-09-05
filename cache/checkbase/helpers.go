package checkbase

import (
	"context"
	"net/http"
	"time"

	"github.com/cerberauth/harnessx/probe"
)

// NewRequest builds an HTTP request for targetURL using pctx's configured
// method, headers, cookies, and bearer token. extra headers (e.g. a
// check-specific cache-buster or injected header) are applied last, so they
// win over ProbeCtx defaults.
func NewRequest(ctx context.Context, targetURL string, pctx *ProbeCtx, extra http.Header) (*http.Request, error) {
	method := pctx.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range pctx.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for _, c := range pctx.Cookies {
		// Secure/HttpOnly/SameSite are response-cookie attributes; this is
		// an outgoing request cookie the caller explicitly configured for
		// probing, so gosec's response-cookie-hardening check doesn't apply.
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) //nolint:gosec // G124: outgoing probe cookie, not a response cookie
	}
	if pctx.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+pctx.BearerToken)
	}
	for k, vs := range extra {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return req, nil
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
	status, header, body, dur, err := probe.Do(ctx, client, req)
	if err != nil {
		return Exchange{}, err
	}
	return Exchange{
		StatusCode: status,
		Header:     header,
		Body:       body,
		Duration:   dur,
		RequestURL: req.URL.String(),
		Method:     req.Method,
	}, nil
}
