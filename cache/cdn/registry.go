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
	expiredValue        = "expired"
	staleValue          = "stale"
	bypassValue         = "bypass"
	revalidatedValue    = "revalidated"
	updatingValue       = "updating"

	// cpdosReference is cited by every KnownIssue documenting a CPDoS-2019
	// finding.
	cpdosReference = "https://cpdos.org/"
)

// cpdosIssue is cited by every CDN/reverse-proxy the original CPDoS research
// (Nguyen, Lo Iacono, Federrath — "Your Cache Has Fallen", ACM CCS 2019)
// confirmed was susceptible to at least one of its three cache-poisoned
// denial-of-service variants: an oversized header (HHO), an HTTP
// meta-character (HMC), or an X-HTTP-Method-Override value (HMO) that
// provokes a cacheable 4xx from the origin.
var cpdosIssue = KnownIssue{
	ID:          "CPDoS-2019",
	Description: "An oversized header, an HTTP meta-character, or an X-HTTP-Method-Override value can provoke a 4xx from the origin that gets cached and served to every subsequent visitor of that URL.",
	Reference:   cpdosReference,
}

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

	// StaticExtensions lists file extensions this CDN is publicly documented
	// to cache by default (subject to the CDN's own standard exclusions,
	// e.g. Set-Cookie/no-store/private) even when the origin sends no
	// explicit Cache-Control — the same "static-extension" surface the
	// cache-deception check (§5) probes generically. Nil when the CDN's
	// default behavior is entirely config-driven (e.g. Fastly's VCL) or not
	// publicly documented — living data, expected to grow via PRs rather
	// than be complete from the start.
	StaticExtensions []string

	// CacheKeyNormalizesBeforeCacheRules documents, when true, that this CDN
	// is known to normalize the request into a cache key (query-string
	// reordering/stripping, Host case-folding, delimiter collapsing, etc.)
	// before evaluating the origin's Cache-Control — so two requests that
	// collapse to the same key can share one cacheability decision even if
	// only one of them actually matched the origin's directives. Left false
	// (the zero value) when the CDN evaluates Cache-Control against the raw
	// request first, or the ordering isn't publicly documented.
	CacheKeyNormalizesBeforeCacheRules bool
	// CacheKeyNotes elaborates on CacheKeyNormalizesBeforeCacheRules with
	// specifics when documented; empty otherwise.
	CacheKeyNotes string

	// KnownIssues cites publicly disclosed CVEs/quirks affecting this CDN's
	// caching behavior, for a reader investigating a finding against it —
	// context, not something this package fingerprints or detects itself.
	KnownIssues []KnownIssue
}

// KnownIssue documents one publicly disclosed CDN-specific caching quirk or
// CVE.
type KnownIssue struct {
	// ID is a CVE identifier (e.g. "CVE-2026-2836") when one was assigned,
	// or a short slug for a disclosed quirk that never got one.
	ID          string
	Description string
	Reference   string
}

// Registry is the extensible table of known CDN/reverse-proxy signatures.
// Append to it (or register additional entries at init time from another
// package) to support a new CDN without touching any detection logic.
var Registry = []Signature{
	{
		Name:              "Cloudflare",
		CacheStatusHeader: "CF-Cache-Status",
		StatusValues: map[string]State{
			hitValue:         StateHit,
			missValue:        StateMiss,
			expiredValue:     StateExpired,
			staleValue:       StateStale,
			bypassValue:      StateBypass,
			"dynamic":        StateDynamic,
			revalidatedValue: StateHit,
			updatingValue:    StateStale,
		},
		AgeHeader:   ageHeader,
		ServerMatch: []string{"cloudflare"},
		ApexDomains: []string{"cloudflare.net"},
		// Source: https://developers.cloudflare.com/cache/concepts/default-cache-behavior/
		StaticExtensions: []string{
			"7z", "apk", "avi", "avif", "bin", "bmp", "bz2", "class", "css", "csv", "dmg", "doc",
			"docx", "ejs", "eot", "eps", "exe", "flac", "gif", "gz", "ico", "iso", "jar", "jpg",
			"jpeg", "js", "mid", "midi", "mkv", "mp3", "mp4", "ogg", "otf", "pdf", "pict", "pls",
			"png", "ppt", "pptx", "ps", "rar", "svg", "svgz", "swf", "tar", "tif", "tiff", "ttf",
			"webm", "webp", "woff", "woff2", "xls", "xlsx", "zip", "zst",
		},
		CacheKeyNormalizesBeforeCacheRules: true,
		CacheKeyNotes:                      "The Host header is lowercased for the cache key before lookup, but forwarded to the origin verbatim — a capitalized-Host cache-poisoning variant was disclosed and fixed in 2020/2021 (see KnownIssues).",
		KnownIssues: []KnownIssue{
			{
				ID:          "cloudflare-403-caching-pre-2021-08-03",
				Description: "Before 2021-08-03, Cloudflare cached 403 responses by default even with no Cache-Control from the origin, letting an attacker force a cacheable 403 (e.g. via a bad Authorization header against an S3/Blob-backed origin) to overwrite a shared object for every subsequent visitor.",
				Reference:   "https://youst.in/posts/cache-poisoning-at-scale/",
			},
			{
				ID:          "CVE-2025-4366",
				Description: "HTTP/1.1 request smuggling in Cloudflare's Pingora proxy layer let a cache-hit response be served without fully draining the incoming request body, enabling cache poisoning on cache hits.",
				Reference:   "https://blog.cloudflare.com/pingora-oss-smuggling-vulnerabilities/",
			},
			{
				ID:          "CVE-2026-2836",
				Description: "Pingora's default HTTP cache key construction used only the URI path, excluding the Host/authority — a cross-tenant cache-poisoning surface in multi-tenant Pingora deployments (Cloudflare's own CDN uses a broader key and wasn't affected).",
				Reference:   "https://blog.cloudflare.com/pingora-oss-smuggling-vulnerabilities/",
			},
			cpdosIssue,
		},
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
		KnownIssues:      []KnownIssue{cpdosIssue},
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
		KnownIssues: []KnownIssue{cpdosIssue},
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
		KnownIssues: []KnownIssue{
			{
				ID:          "cpdos-cloudfront-400-default-cache",
				Description: "The most severely affected CDN in the original 2019 CPDoS study: CloudFront cached 400 Bad Request responses by default with no explicit Cache-Control from the origin, across all three CPDoS variants. AWS fixed this by no longer caching 400s by default.",
				Reference:   cpdosReference,
			},
		},
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
		KnownIssues:      []KnownIssue{cpdosIssue},
	},
	{
		Name:              "Vercel",
		CacheStatusHeader: "X-Vercel-Cache",
		StatusValues: map[string]State{
			hitValue:    StateHit,
			missValue:   StateMiss,
			staleValue:  StateStale,
			bypassValue: StateBypass,
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
	{
		// Cloud CDN doesn't emit a HIT/MISS header by default — that requires
		// the operator to opt in to a custom response header bound to the
		// {cdn_cache_status} URL-map variable, whose name isn't fixed, so
		// there's no universal CacheStatusHeader to register. Fingerprinting
		// instead relies on the "Via: 1.1 google" header Google's edge
		// network adds to every proxied response.
		// Source: https://docs.cloud.google.com/cdn/docs/caching
		Name:        "Google Cloud CDN",
		AgeHeader:   ageHeader,
		ViaMatch:    []string{"1.1 google"},
		KnownIssues: []KnownIssue{cpdosIssue},
	},
	{
		Name:              "Azure Front Door",
		CacheStatusHeader: genericXCacheHeader,
		StatusValues: map[string]State{
			"tcp_hit":         StateHit,
			"tcp_remote_hit":  StateHit,
			"tcp_miss":        StateMiss,
			"revalidated_hit": StateHit,
			"private_nostore": StateBypass,
			"config_nocache":  StateBypass,
		},
		AgeHeader:   ageHeader,
		ApexDomains: []string{"azurefd.net"},
		// X-Cache-Info carries an L1/L2 tier code (e.g. "L1_T2") on a cache
		// hit served from a regional tier behind the edge.
		// Source: https://learn.microsoft.com/en-us/azure/frontdoor/front-door-caching
		MultiTierHeaders: []string{"X-Cache-Info"},
		KnownIssues: []KnownIssue{
			{
				ID:          "CVE-2019-0941",
				Description: "The CVE Microsoft assigned to its fix for the CPDoS (2019) cache-poisoned-DoS variants affecting Azure's edge caching.",
				Reference:   cpdosReference,
			},
			cpdosIssue,
		},
	},
	{
		// ServerMatch is deliberately omitted: "nginx" alone is the Server
		// header of countless plain origins that aren't acting as a caching
		// reverse proxy (proxy_cache is opt-in config, not a default), so
		// matching on it would misidentify most nginx-fronted sites as a
		// cache. X-Cache-Status is itself opt-in (an operator must
		// `add_header X-Cache-Status $upstream_cache_status;`), so its mere
		// presence is already a reliable, low-false-positive signal — it's
		// picked up by Detect's generic per-registry-entry header fallback
		// without needing a Server/Via fingerprint first.
		Name:              "Nginx (proxy_cache)",
		CacheStatusHeader: "X-Cache-Status",
		StatusValues: map[string]State{
			hitValue:         StateHit,
			missValue:        StateMiss,
			bypassValue:      StateBypass,
			expiredValue:     StateExpired,
			staleValue:       StateStale,
			updatingValue:    StateStale,
			revalidatedValue: StateHit,
		},
		AgeHeader: ageHeader,
	},
	{
		Name:              "KeyCDN",
		CacheStatusHeader: genericXCacheHeader,
		StatusValues: map[string]State{
			hitValue:         StateHit,
			missValue:        StateMiss,
			expiredValue:     StateExpired,
			revalidatedValue: StateHit,
			updatingValue:    StateStale,
			staleValue:       StateStale,
		},
		AgeHeader:   ageHeader,
		ServerMatch: []string{"keycdn-engine"},
		ApexDomains: []string{"kxcdn.com"},
	},
	{
		Name:              "Bunny CDN",
		CacheStatusHeader: "CDN-Cache",
		StatusValues: map[string]State{
			hitValue:  StateHit,
			missValue: StateMiss,
		},
		AgeHeader:   ageHeader,
		ServerMatch: []string{"bunnycdn"},
		ApexDomains: []string{"b-cdn.net"},
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
