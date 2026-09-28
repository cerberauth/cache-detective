package checkbase

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
)

// CacheBusterMode selects how a CacheBusterProbe carries its per-attempt
// token: as a query parameter, a request header, or both. Query is the
// default — the same form Param Miner uses, since it's the form least
// likely to be stripped before reaching the origin. Mode exists so a
// target whose CDN normalizes/drops unknown query params (or, less
// commonly, unknown headers) can be pointed at whichever form survives.
type CacheBusterMode string

const (
	// CacheBusterQuery carries the token as a query parameter. Default.
	CacheBusterQuery CacheBusterMode = "query"
	// CacheBusterHeader carries the token as a request header instead.
	CacheBusterHeader CacheBusterMode = "header"
	// CacheBusterBoth carries the token as both, for a target where it's
	// unclear which form the fronting cache preserves.
	CacheBusterBoth CacheBusterMode = "both"
)

// CacheBusterConfig configures how every active-probing check (§5) isolates
// its poison/confirm request pairs from a resource's real, canonical cache
// entry: Param Miner's "always add a cache-buster, so testing doesn't
// poison real users" approach, applied here so a poisoned/error response an
// aggressive check deliberately provokes lands on a cache entry keyed by a
// random per-attempt token instead of the plain resource URL — one no real
// user's request to that URL ever reads from or writes to.
type CacheBusterConfig struct {
	// Mode selects query param, header, or both. Defaults to
	// CacheBusterQuery.
	Mode CacheBusterMode

	// QueryParam is the query-string key the token is set under in query
	// mode. Defaults to "cd_cachebuster".
	QueryParam string

	// HeaderName is the request header the token is set on in header mode.
	// Defaults to "X-Cache-Detective-Buster".
	HeaderName string
}

// withDefaults returns a copy of c with zero-value fields filled in.
func (c CacheBusterConfig) withDefaults() CacheBusterConfig {
	if c.Mode == "" {
		c.Mode = CacheBusterQuery
	}
	if c.QueryParam == "" {
		c.QueryParam = "cd_cachebuster"
	}
	if c.HeaderName == "" {
		c.HeaderName = "X-Cache-Detective-Buster"
	}
	return c
}

// CacheBusterProbe is one isolated, per-attempt probing target: resourceURL
// (and/or an extra header) carrying a random token unique to that attempt.
type CacheBusterProbe struct {
	// URL is the resource URL with the buster token applied per Mode (a
	// query param added in CacheBusterQuery/CacheBusterBoth mode; unchanged
	// in CacheBusterHeader mode).
	URL string

	// Header carries the buster token per Mode (nil in CacheBusterQuery
	// mode). Merge it into a request's headers with MergeHeader.
	Header http.Header
}

// NewCacheBusterProbe generates a fresh random token and returns the
// CacheBusterProbe for resourceURL under pctx's CacheBuster config. Call it
// once per probing "attempt" — e.g. once per candidate header in the
// unkeyed-header check, or once per CPDoS variant — and reuse the returned
// URL/Header for every request that attempt makes (poison, then confirm).
// Reusing the same token across that pair is what lets the confirm request
// land on the exact cache entry the poison request just wrote to, without
// either of them ever touching the resource's real canonical URL.
func NewCacheBusterProbe(resourceURL string, pctx *ProbeCtx) (CacheBusterProbe, error) {
	token, err := randomCacheBusterToken()
	if err != nil {
		return CacheBusterProbe{}, err
	}

	cfg := pctx.CacheBuster.withDefaults()

	bustedURL := resourceURL
	if cfg.Mode != CacheBusterHeader {
		u, err := url.Parse(resourceURL)
		if err != nil {
			return CacheBusterProbe{}, err
		}
		q := u.Query()
		q.Set(cfg.QueryParam, token)
		u.RawQuery = q.Encode()
		bustedURL = u.String()
	}

	var header http.Header
	if cfg.Mode != CacheBusterQuery {
		header = http.Header{cfg.HeaderName: {token}}
	}

	return CacheBusterProbe{URL: bustedURL, Header: header}, nil
}

// MergeHeader returns a new http.Header containing every value from a and
// b, for combining a CacheBusterProbe.Header with a check's own
// attack-specific extra headers before passing them to NewRequest.
func MergeHeader(a, b http.Header) http.Header {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	merged := make(http.Header, len(a)+len(b))
	for k, vs := range a {
		merged[k] = append(merged[k], vs...)
	}
	for k, vs := range b {
		merged[k] = append(merged[k], vs...)
	}
	return merged
}

func randomCacheBusterToken() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
