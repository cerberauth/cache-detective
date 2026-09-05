// Package checkbase holds the shared per-scan context and request-building
// helpers every cache-detective check depends on.
package checkbase

import (
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/x/reportx/harnessreport"
)

// CheckDef aliases harnessx/checkdef's declarative check metadata, so
// individual check packages don't need to import checkdef directly.
type CheckDef = checkdef.CheckDef

// ProbeResult aliases the shared harnessreport bridge type. Vulnerable is
// only meaningful for the security checks (§5); the analysis checks (§1-4,
// §6) report their findings as harnessx.Observations instead and leave
// Vulnerable false.
type ProbeResult = harnessreport.Result

// ProbeCtx is the scan-wide configuration shared by every check, attached
// to harnessx.Target.Data: the one piece of state that differs between
// checks is pulled out of here, everything else (skip wiring, error
// handling, probe dispatch) is shared.
type ProbeCtx struct {
	// Probe is the harnessx/probe.Probe used for every outgoing request —
	// carries retry, rate-limit compliance, and User-Agent injection.
	Probe *probe.Probe

	// Method is the HTTP method to test. Defaults to GET.
	Method string

	// Headers are additional request headers sent with every probe request
	// (e.g. custom cache-key inputs to test, or app-specific auth headers).
	Headers map[string][]string

	// Cookies are sent with every probe request, e.g. a session cookie for
	// authenticated-cache-response testing.
	Cookies []Cookie

	// BearerToken, if set, is sent as "Authorization: Bearer <token>".
	BearerToken string

	// Authenticated marks the request under test as carrying credentials,
	// for the "authenticated response marked cacheable" check (§1). It
	// defaults to true when BearerToken or Cookies is non-empty, but can be
	// forced independently (e.g. a custom auth header with no cookie/bearer).
	Authenticated bool

	// RequestCount is how many probe requests the live cache-state check
	// (§2) issues per resource to observe HIT/MISS/hit-ratio patterns.
	RequestCount int

	// RequestInterval spaces consecutive probe requests to a resource.
	RequestInterval time.Duration

	// Timeout bounds each individual probe request.
	Timeout time.Duration

	// Aggressive gates every check in §5 (cache poisoning / cache deception
	// probing) plus any other check that could pollute a shared cache.
	// Non-destructive by default: false unless explicitly opted into.
	Aggressive bool

	// MaxAggressiveRequests hard-caps the number of extra probe requests an
	// aggressive-mode check may issue per resource, regardless of what the
	// check itself would otherwise attempt. Applies even when Aggressive is
	// true, so a misconfigured check can't run away against a live target.
	MaxAggressiveRequests int

	// Resources is the resolved list of URLs to probe. DiscoveryCheck turns
	// this into the harnessx.Resource list every per-resource check runs
	// against.
	Resources []ResourceSpec
}

// SeverityKey is the Observation.Metadata key every check uses to attach an
// advisory severity hint to a finding. harnessreport scores a finding from
// its *check's* CheckDef.CVSSScore (set once per check, not per
// observation), so this key exists for tooling that reads
// Observation.Metadata directly and wants a finer-grained hint than that
// check-wide score — see the "Design notes" section of the README for why
// findings are split across CheckIDs by severity instead.
const SeverityKey = "severity"

// Severity hint values for SeverityKey.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// ResourceSpec is one URL to probe, resolved ahead of the scan by the CLI
// layer (a single --url flag, a list file, a sitemap, a .har import, or a
// same-origin crawl — see the cache/crawl package) and attached to
// ProbeCtx.Resources for DiscoveryCheck to turn into harnessx.Resources.
type ResourceSpec struct {
	ID     string
	URL    string
	Method string
}

// Cookie is a minimal, dependency-free stand-in for http.Cookie's fields
// that matter for probing (Name/Value), so callers building a ProbeCtx
// don't need to import net/http just to set one.
type Cookie struct {
	Name  string
	Value string
}

// WithDefaults returns a copy of c with zero-value fields filled in with
// sane defaults.
func (c ProbeCtx) WithDefaults() ProbeCtx {
	if c.Method == "" {
		c.Method = "GET"
	}
	if c.RequestCount <= 0 {
		c.RequestCount = 1
	}
	if c.Timeout <= 0 {
		c.Timeout = 15 * time.Second
	}
	if c.MaxAggressiveRequests <= 0 {
		c.MaxAggressiveRequests = 10
	}
	if c.BearerToken != "" || len(c.Cookies) > 0 {
		c.Authenticated = true
	}
	return c
}

const (
	// CheckIDDiscovery seeds the harnessx.Resource list every per-resource
	// check depends on, from ProbeCtx.Resources (the URL(s) supplied on the
	// command line, a list file, a sitemap, a .har import, or a crawl —
	// see the cache/crawl package).
	CheckIDDiscovery harnessx.CheckID = "discovery"
	// CheckIDCacheability is the §1 cacheability-analysis check.
	CheckIDCacheability harnessx.CheckID = "cacheability"
	// CheckIDLiveState is the §2 live cache-state-detection check.
	CheckIDLiveState harnessx.CheckID = "live-state"
	// CheckIDFingerprint is the §3 CDN/proxy fingerprinting check.
	CheckIDFingerprint harnessx.CheckID = "fingerprint"
	// CheckIDVaryKey is the §4 cache-key & Vary analysis check.
	CheckIDVaryKey harnessx.CheckID = "vary-key"
	// CheckIDUnkeyedHeader is the §5 unkeyed-header-injection security check.
	CheckIDUnkeyedHeader harnessx.CheckID = "unkeyed-header-injection"
	// CheckIDCacheDeception is the §5 cache-deception path-confusion check.
	CheckIDCacheDeception harnessx.CheckID = "cache-deception"
	// CheckIDErrorCaching is the §5 error-response-caching check.
	CheckIDErrorCaching harnessx.CheckID = "error-caching"
	// CheckIDResponseSplitting is the §5 response-splitting-via-cache-key
	// manipulation check.
	CheckIDResponseSplitting harnessx.CheckID = "response-splitting"
	// CheckIDConsistency is the §6 response-consistency & correctness check.
	CheckIDConsistency harnessx.CheckID = "consistency"
	// CheckIDAuthCacheable is the security-relevant "authenticated response
	// marked cacheable" misconfiguration check, split out from
	// CheckIDCacheability so it can carry its own CVSS/CWE severity.
	CheckIDAuthCacheable harnessx.CheckID = "authenticated-cacheable"
)
