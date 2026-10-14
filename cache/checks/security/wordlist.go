package security

// defaultHeaderWordlist seeds header-based unkeyed-input mining with
// headers frequently reflected into a response (redirects, canonical
// links, asset URLs) without being folded into the cache key — Kettle's
// "Practical Web Cache Poisoning" (2018) and Param Miner's default header
// list.
var defaultHeaderWordlist = []string{
	"X-Forwarded-Host",
	"X-Forwarded-Scheme",
	"X-Forwarded-Proto",
	"X-Forwarded-Server",
	"X-Host",
	"X-Original-URL",
	"X-Rewrite-URL",
}

// defaultCookieWordlist seeds cookie-based unkeyed-input mining with names
// commonly used to toggle a response variant (feature flags, locale,
// device hints) without ever being declared in Vary or folded into the
// cache key.
var defaultCookieWordlist = []string{
	"debug",
	"beta",
	"preview",
	"test",
	langParam,
	"language",
	"locale",
	"region",
	"country",
	"currency",
	"theme",
	"mobile",
}

// defaultParamWordlist seeds query-parameter-based unkeyed-input mining
// with names commonly stripped or ignored by a fronting cache's key
// normalization (tracking/analytics params, debug/preview toggles) while
// still reaching — and influencing — the origin.
var defaultParamWordlist = []string{
	"debug",
	"test",
	"preview",
	"callback",
	"jsonp",
	"redirect",
	"return_url",
	"next",
	"utm_source",
	"utm_campaign",
	"ref",
	langParam,
	"locale",
}
