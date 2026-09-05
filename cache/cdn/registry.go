// Package cdn holds CDN/reverse-proxy signature data — header conventions,
// cache-status vocabularies, and CNAME apex domains — as a data table
// rather than inline conditionals, so a new CDN is added by appending an
// entry instead of touching detection code (per the project's architecture
// guidance).
package cdn

import "strings"

// State is a normalized live cache state, independent of any one CDN's
// header vocabulary.
type State string

const (
	StateHit     State = "HIT"
	StateMiss    State = "MISS"
	StateStale   State = "STALE"
	StateExpired State = "EXPIRED"
	StateBypass  State = "BYPASS"
	StateDynamic State = "DYNAMIC" // explicitly marked as never cached (e.g. Cloudflare "DYNAMIC")
	StateUnknown State = "UNKNOWN"
)

// Header/value literals shared by more than one Registry entry, pulled out
// as constants rather than repeated inline.
const (
	// ageHeader is the standard header nearly every CDN in Registry uses to
	// report a cached response's age in seconds.
	ageHeader = "Age"
	// genericXCacheHeader is the header name several unrelated CDNs (Fastly,
	// Akamai, CloudFront, Varnish, Pantheon) all happen to reuse, each with
	// its own value vocabulary — see Detect's disambiguation-by-fingerprint
	// logic in detect.go.
	genericXCacheHeader = "X-Cache"
	hitValue            = "hit"
	missValue           = "miss"
)

// Signature describes one CDN/reverse-proxy's cache-observability
// conventions: which header carries its cache-status verdict, how that
// verdict's values map to a normalized State, and what to match against
// Server/Via headers or CNAME apex domains for fingerprinting (§3).
type Signature struct {
	Name string

	// CacheStatusHeader is the header this CDN uses to report HIT/MISS/etc,
	// e.g. "CF-Cache-Status" for Cloudflare.
	CacheStatusHeader string
	// StatusValues maps that header's raw values (matched case-insensitively,
	// as a prefix — some CDNs append detail after the verdict, e.g. Fastly's
	// "HIT-CLUSTER") to a normalized State.
	StatusValues map[string]State

	// AgeHeader is the header carrying the response's age in seconds in the
	// cache, almost always the standard "Age" header.
	AgeHeader string

	// ServerMatch / ViaMatch are case-insensitive substrings matched against
	// the Server / Via response headers to fingerprint this CDN when no
	// cache-status header is present.
	ServerMatch []string
	ViaMatch    []string

	// ApexDomains are CNAME apex domains associated with this CDN, e.g.
	// "cloudflare.net" — matched as a suffix against a resolved CNAME chain.
	ApexDomains []string

	// MultiTierHeaders lists additional headers this CDN emits when a
	// request traversed more than one cache tier (edge + shield/regional),
	// e.g. Fastly's "X-Served-By" carrying multiple POP identifiers.
	MultiTierHeaders []string
}

// Registry is the extensible table of known CDN/reverse-proxy signatures.
// Append to it (or register additional entries at init time from another
// package) to support a new CDN without touching any detection logic.
var Registry = []Signature{
	{
		Name:              "Cloudflare",
		CacheStatusHeader: "CF-Cache-Status",
		StatusValues: map[string]State{
			hitValue:      StateHit,
			missValue:     StateMiss,
			"expired":     StateExpired,
			"stale":       StateStale,
			"bypass":      StateBypass,
			"dynamic":     StateDynamic,
			"revalidated": StateHit,
			"updating":    StateStale,
		},
		AgeHeader:   ageHeader,
		ServerMatch: []string{"cloudflare"},
		ApexDomains: []string{"cloudflare.net"},
	},
	{
		Name:              "Fastly",
		CacheStatusHeader: genericXCacheHeader,
		StatusValues: map[string]State{
			hitValue:  StateHit,
			missValue: StateMiss,
			"pass":    StateBypass,
		},
		AgeHeader:        ageHeader,
		ServerMatch:      []string{"fastly"},
		ViaMatch:         []string{"varnish"},
		ApexDomains:      []string{"fastly.net", "fastlylb.net"},
		MultiTierHeaders: []string{"X-Served-By", "X-Cache-Hits"},
	},
	{
		Name:              "Akamai",
		CacheStatusHeader: genericXCacheHeader,
		StatusValues: map[string]State{
			"tcp_hit":         StateHit,
			"tcp_miss":        StateMiss,
			"tcp_refresh_hit": StateHit,
			"tcp_expired_hit": StateStale,
			"tcp_ims_hit":     StateHit,
		},
		AgeHeader:   ageHeader,
		ServerMatch: []string{"akamaighost"},
		ApexDomains: []string{"akamaiedge.net", "akamaitechnologies.com", "akamai.net"},
	},
	{
		Name:              "Amazon CloudFront",
		CacheStatusHeader: genericXCacheHeader,
		StatusValues: map[string]State{
			"hit from cloudfront":           StateHit,
			"miss from cloudfront":          StateMiss,
			"refreshhit from cloudfront":    StateHit,
			"error from cloudfront":         StateBypass,
			"redirecthit from cloudfront":   StateHit,
			"limitexceeded from cloudfront": StateBypass,
		},
		AgeHeader:   ageHeader,
		ViaMatch:    []string{"cloudfront"},
		ApexDomains: []string{"cloudfront.net"},
	},
	{
		Name:              "Varnish",
		CacheStatusHeader: genericXCacheHeader,
		StatusValues: map[string]State{
			hitValue:  StateHit,
			missValue: StateMiss,
		},
		AgeHeader:        ageHeader,
		ViaMatch:         []string{"varnish"},
		MultiTierHeaders: []string{"X-Varnish"},
	},
	{
		Name:              "Vercel",
		CacheStatusHeader: "X-Vercel-Cache",
		StatusValues: map[string]State{
			hitValue:    StateHit,
			missValue:   StateMiss,
			"stale":     StateStale,
			"bypass":    StateBypass,
			"prerender": StateHit,
		},
		AgeHeader:   ageHeader,
		ServerMatch: []string{"vercel"},
		ApexDomains: []string{"vercel-dns.com", "vercel.app"},
	},
	{
		Name:              "Netlify",
		CacheStatusHeader: "X-Nf-Request-Id",
		StatusValues:      map[string]State{}, // Netlify doesn't emit a HIT/MISS verdict; presence + Age/Cache-Control drives the heuristic fallback.
		AgeHeader:         ageHeader,
		ServerMatch:       []string{"netlify"},
		ApexDomains:       []string{"netlify.app", "netlifyglobalcdn.com"},
	},
	{
		Name:              "Pantheon",
		CacheStatusHeader: genericXCacheHeader,
		StatusValues: map[string]State{
			hitValue:  StateHit,
			missValue: StateMiss,
		},
		AgeHeader:   ageHeader,
		ServerMatch: []string{"pantheon"},
		ApexDomains: []string{"pantheonsite.io"},
	},
}

// Register appends a Signature to Registry — for embedding tools that know
// about additional/private CDN deployments.
func Register(sig Signature) {
	Registry = append(Registry, sig)
}

// MatchServer returns the first Signature whose ServerMatch or ViaMatch
// matches server/via (case-insensitive substring), or false if none match.
func MatchServer(server, via string) (Signature, bool) {
	server, via = strings.ToLower(server), strings.ToLower(via)
	for _, sig := range Registry {
		for _, m := range sig.ServerMatch {
			if server != "" && strings.Contains(server, strings.ToLower(m)) {
				return sig, true
			}
		}
		for _, m := range sig.ViaMatch {
			if via != "" && strings.Contains(via, strings.ToLower(m)) {
				return sig, true
			}
		}
	}
	return Signature{}, false
}

// MatchCNAME returns the first Signature whose ApexDomains matches a suffix
// of any hop in the CNAME chain, or false if none match.
func MatchCNAME(chain []string) (Signature, bool) {
	for _, hop := range chain {
		hop = strings.ToLower(strings.TrimSuffix(hop, "."))
		for _, sig := range Registry {
			for _, apex := range sig.ApexDomains {
				if strings.HasSuffix(hop, strings.ToLower(apex)) {
					return sig, true
				}
			}
		}
	}
	return Signature{}, false
}

// Normalize maps a raw cache-status header value to a normalized State
// using sig's StatusValues, matching case-insensitively and by prefix (some
// CDNs append cluster/detail info after the verdict).
func (sig Signature) Normalize(raw string) (State, bool) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if v, ok := sig.StatusValues[raw]; ok {
		return v, true
	}
	for k, v := range sig.StatusValues {
		if strings.HasPrefix(raw, k) {
			return v, true
		}
	}
	return StateUnknown, false
}
