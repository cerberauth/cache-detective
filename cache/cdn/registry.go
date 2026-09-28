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
	staleValue          = "stale"
	bypassValue         = "bypass"
)

// commonStaticExtensions are the file extensions nearly every CDN in
// Registry treats as cacheable by default, factored out since most
// StaticExtensions lists are this set plus a couple of vendor-specific
// additions.
var commonStaticExtensions = []string{".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2"}

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

	// StaticExtensions are file extensions this CDN's default configuration
	// treats as cacheable at the edge regardless of the origin's
	// Cache-Control — the exact surface the cache-deception check (§5)
	// probes with path-confusion suffixes. Documented per-CDN here instead
	// of hardcoded in that check, so a vendor changing its default list is a
	// data edit.
	StaticExtensions []string

	// KeyNormalization is a free-text note on how/when this CDN normalizes
	// cache-key inputs — query-string ordering/stripping, delimiter
	// handling, case folding — relative to Vary and Cache-Control
	// evaluation. It's documentation for a human interpreting an unexpected
	// HIT/MISS, not something Detect matches against.
	KeyNormalization string

	// Quirks lists known, disclosed CDN-specific caching behaviors, CVEs, or
	// incidents relevant to cache-poisoning/deception risk assessment (see
	// Quirk) — kept as data so a newly disclosed issue is a Registry edit,
	// not a code change.
	Quirks []Quirk
}

// Quirk documents one known, disclosed CDN-specific caching behavior, CVE,
// or incident — context for interpreting a scan finding against that CDN,
// not something cache-detective probes for directly.
type Quirk struct {
	// ID is a short, stable identifier: a CVE ID (e.g. "CVE-2026-2836") or a
	// slug for an undated/non-CVE quirk (e.g. "cpdos-2019").
	ID string
	// Description explains the behavior/vulnerability in one or two
	// sentences: what it affected, what made it exploitable, and (if fixed)
	// roughly when/how.
	Description string
	// Reference is a URL to the disclosure, advisory, or vendor writeup.
	Reference string
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
			staleValue:    StateStale,
			bypassValue:   StateBypass,
			"dynamic":     StateDynamic,
			"revalidated": StateHit,
			"updating":    StateStale,
		},
		AgeHeader:        ageHeader,
		ServerMatch:      []string{"cloudflare"},
		ApexDomains:      []string{"cloudflare.net"},
		StaticExtensions: append(commonStaticExtensions, ".webp", ".pdf", ".mp4", ".zip"),
		KeyNormalization: "Default cache key is scheme+host+path; the query string is included verbatim (not reordered) unless a Cache Rules \"Custom Key\" strips/reorders it. Cacheability is decided first by file extension (see StaticExtensions), then by origin Cache-Control — an extensionless/HTML response isn't cached by default regardless of Cache-Control.",
		Quirks: []Quirk{
			cpdosQuirk,
			{
				ID:          "cf-error-status-default-ttl",
				Description: "Cloudflare caches select error responses (404, 410, and other configured status codes) for a short default TTL even with no explicit Cache-Control from the origin, when the request matches a cacheable extension/rule — a WAF- or origin-generated error can end up served to other users for that window if not excluded.",
				Reference:   "https://developers.cloudflare.com/cache/concepts/default-cache-behavior/",
			},
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
		StaticExtensions: commonStaticExtensions,
		KeyNormalization: "VCL-defined: the default Fastly Varnish Configuration Language (VCL) hashes scheme+host+path and, unless overridden, the full query string (unordered, i.e. present verbatim) — most production configs add explicit vcl_hash logic to strip tracking params or normalize delimiters before hashing, so behavior varies per service.",
		Quirks:           []Quirk{cpdosQuirk},
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
		AgeHeader:        ageHeader,
		ServerMatch:      []string{"akamaighost"},
		ApexDomains:      []string{"akamaiedge.net", "akamaitechnologies.com", "akamai.net"},
		StaticExtensions: append(commonStaticExtensions, ".pdf"),
		KeyNormalization: "Cache key composition (host, path, query-string inclusion/exclusion, case folding) is set per Property in Akamai's Property Manager rule tree (\"Caching\"/\"Cache Key Query Parameters\" behaviors) — there is no single platform-wide default; check the property config rather than assuming query strings are ignored.",
		Quirks:           []Quirk{cpdosQuirk},
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
		AgeHeader:        ageHeader,
		ViaMatch:         []string{"cloudfront"},
		ApexDomains:      []string{"cloudfront.net"},
		StaticExtensions: commonStaticExtensions,
		KeyNormalization: "Cache key is set per distribution by a cache policy: the managed \"CachingOptimized\" policy keys on host+path only (query strings, headers, and cookies all excluded by default); a custom policy can add specific query params (allowlist, sorted) or headers/cookies to the key.",
		Quirks:           []Quirk{cpdosQuirk},
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
		KeyNormalization: "Default vcl_hash hashes req.url (full path + query string, verbatim, no reordering) plus req.http.host — most deployments add custom VCL to strip query params or normalize delimiters, so the effective key depends entirely on the site's VCL.",
		Quirks:           []Quirk{cpdosQuirk},
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
		AgeHeader:        ageHeader,
		ServerMatch:      []string{"vercel"},
		ApexDomains:      []string{"vercel-dns.com", "vercel.app"},
		StaticExtensions: commonStaticExtensions,
		KeyNormalization: "Static assets under /_next/static/ and other build-hashed paths are cached indefinitely by filename (the hash makes the path itself the cache key); everything else follows the deployment's own Cache-Control, with the query string included in the key verbatim.",
	},
	{
		Name:              "Netlify",
		CacheStatusHeader: "X-Nf-Request-Id",
		StatusValues:      map[string]State{}, // Netlify doesn't emit a HIT/MISS verdict; presence + Age/Cache-Control drives the heuristic fallback.
		AgeHeader:         ageHeader,
		ServerMatch:       []string{"netlify"},
		ApexDomains:       []string{"netlify.app", "netlifyglobalcdn.com"},
		StaticExtensions:  commonStaticExtensions,
		KeyNormalization:  "Immutable, content-hashed asset paths are cached indefinitely; HTML and non-hashed paths follow the site's own Cache-Control, keyed on host+path+query string as-is.",
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
		Name:              "Google Cloud CDN",
		CacheStatusHeader: "", // Cloud CDN does not add a client-visible HIT/MISS header by default; cache status is only available via Cloud Logging/Monitoring — see the timing/Age fallback for live-state inference.
		StatusValues:      map[string]State{},
		AgeHeader:         ageHeader,
		ServerMatch:       []string{"google frontend"},
		ViaMatch:          []string{"google"},
		StaticExtensions:  commonStaticExtensions,
		KeyNormalization:  "Cache key composition (host, path, query-string inclusion, protocol) is configured per backend service's CacheKeyPolicy; the default policy includes the full host, path, and query string verbatim.",
	},
	{
		Name:              "Azure Front Door",
		CacheStatusHeader: genericXCacheHeader,
		StatusValues: map[string]State{
			"tcp_hit":        StateHit,
			"tcp_miss":       StateMiss,
			"tcp_remote_hit": StateHit,
			"config_nocache": StateBypass,
		},
		AgeHeader:        ageHeader,
		ApexDomains:      []string{"azurefd.net", "azureedge.net"},
		StaticExtensions: commonStaticExtensions,
		KeyNormalization: "Cache key defaults to scheme+host+path+query string verbatim; caching duration/query-string handling (include all, ignore, or a specific allowlist) is set per route in the \"Caching\" rule set.",
	},
	{
		Name:              "Nginx",
		CacheStatusHeader: "X-Cache-Status",
		StatusValues: map[string]State{
			hitValue:      StateHit,
			missValue:     StateMiss,
			"expired":     StateExpired,
			staleValue:    StateStale,
			"updating":    StateStale,
			"revalidated": StateHit,
			bypassValue:   StateBypass,
		},
		AgeHeader:        ageHeader,
		ServerMatch:      []string{"nginx"},
		StaticExtensions: commonStaticExtensions,
		KeyNormalization: "No built-in default: proxy_cache_key is set explicitly in nginx.conf (commonly $scheme$host$request_uri, i.e. the query string included verbatim) — behavior, including whether ';'/'&' delimiters or param ordering are normalized, is entirely config-defined rather than a vendor default.",
	},
	{
		Name:              "KeyCDN",
		CacheStatusHeader: genericXCacheHeader,
		StatusValues: map[string]State{
			hitValue:  StateHit,
			missValue: StateMiss,
		},
		AgeHeader:        ageHeader,
		ServerMatch:      []string{"keycdn-engine"},
		ApexDomains:      []string{"kxcdn.com"},
		StaticExtensions: commonStaticExtensions,
		KeyNormalization: "Default cache key is host+path; query strings are ignored (stripped from the key) unless \"Query String\" caching is explicitly enabled on the zone, in which case the full query string is included verbatim.",
	},
	{
		Name:              "Bunny CDN",
		CacheStatusHeader: "CDN-Cache",
		StatusValues: map[string]State{
			hitValue:   StateHit,
			missValue:  StateMiss,
			staleValue: StateStale,
		},
		AgeHeader:        ageHeader,
		ServerMatch:      []string{"bunnycdn"},
		ApexDomains:      []string{"b-cdn.net"},
		StaticExtensions: append(commonStaticExtensions, ".webp"),
		KeyNormalization: "Default cache key is host+path; query strings are ignored by default unless \"Query String Vary\" is enabled on the pull zone, which adds the full, verbatim query string to the key.",
	},
}

// cpdosQuirk documents the 2019 Cache-Poisoned Denial-of-Service research
// (CPDoS): oversized headers, meta-characters, or an overridden HTTP method
// in a request could provoke an origin error that the fronting cache then
// stored and served in place of the real resource. Shared by every CDN the
// original disclosure tested, rather than duplicated per entry.
var cpdosQuirk = Quirk{
	ID:          "cpdos-2019",
	Description: "Cache-Poisoned Denial-of-Service: an attacker-provoked origin error (oversized header, HTTP meta-character, or overridden method) gets cached and served to other users in place of the real resource, denying access without needing a high-volume flood. This CDN was one of those studied in the original 2019 disclosure — always confirm current behavior, since most vendors shipped mitigations afterward.",
	Reference:   "https://cpdos.org/",
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

// AllStaticExtensions returns the deduplicated union of every Registry
// entry's StaticExtensions, in Registry order — real-world CDN
// default-cached extensions for seeding the cache-deception check's
// path-confusion probe suffixes, rather than a fixed guess.
func AllStaticExtensions() []string {
	seen := make(map[string]bool)
	var out []string
	for _, sig := range Registry {
		for _, ext := range sig.StaticExtensions {
			if !seen[ext] {
				seen[ext] = true
				out = append(out, ext)
			}
		}
	}
	return out
}
