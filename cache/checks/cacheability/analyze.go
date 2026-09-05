package cacheability

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cerberauth/harnessx"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// AnalysisResult is the structured outcome of analyzing one response for
// cacheability. It's stored as the cacheability Check's per-resource
// Result.Data so downstream checks (e.g. the authenticated-cacheable
// security check, or live-state's cross-check against declared freshness)
// can reuse it without re-requesting the resource.
type AnalysisResult struct {
	Method     string
	StatusCode int

	CacheControl CacheControl
	ExpiresRaw   string
	Expires      *time.Time
	Pragma       string
	Vary         []string

	HasETag         bool
	HasLastModified bool

	Cacheable bool
	Reasons   []string

	Authenticated bool

	// Findings are the misconfigurations/notable observations detected
	// during analysis (conflicting directives, missing validators, ...).
	// The authenticated-cacheable finding is deliberately excluded here —
	// see the sibling AuthCacheableCheck, which owns that CVSS/CWE-bearing
	// finding as its own check so it carries distinct severity metadata.
	Findings []harnessx.Observation
}

// Analyze inspects a single HTTP response and determines whether it is
// cacheable per RFC 9111 semantics, flagging conflicting/redundant
// directives and missing validators along the way.
func Analyze(method string, statusCode int, header http.Header, authenticated bool) AnalysisResult {
	cc := ParseCacheControl(header.Get("Cache-Control"))
	res := AnalysisResult{
		Method:          strings.ToUpper(method),
		StatusCode:      statusCode,
		CacheControl:    cc,
		Pragma:          header.Get("Pragma"),
		Vary:            parseVary(header.Get("Vary")),
		HasETag:         header.Get("ETag") != "",
		HasLastModified: header.Get("Last-Modified") != "",
		Authenticated:   authenticated,
	}

	if raw := header.Get("Expires"); raw != "" {
		res.ExpiresRaw = raw
		if t, err := http.ParseTime(raw); err == nil {
			res.Expires = &t
		}
	}

	res.Cacheable, res.Reasons = determineCacheable(res)
	res.Findings = append(res.Findings, conflictFindings(cc)...)
	res.Findings = append(res.Findings, pragmaFinding(header, cc))
	if res.Cacheable && !res.HasETag && !res.HasLastModified {
		res.Findings = append(res.Findings, harnessx.Observation{
			Title:       "Cacheable response missing validators",
			Description: "response is cacheable but carries neither ETag nor Last-Modified, so a cache can't revalidate it without a full re-fetch once it expires",
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityLow},
		})
	}

	// Drop nil placeholders from pragmaFinding when there was nothing to report.
	filtered := res.Findings[:0]
	for _, f := range res.Findings {
		if f.Title != "" {
			filtered = append(filtered, f)
		}
	}
	res.Findings = filtered

	return res
}

func determineCacheable(res AnalysisResult) (bool, []string) {
	cc := res.CacheControl

	if cc.NoStore {
		return false, []string{"Cache-Control: no-store forbids storage"}
	}

	explicitFreshness := cc.MaxAge != nil || cc.SMaxAge != nil || res.Expires != nil

	if !MethodCanBeMadeCacheable(res.Method) {
		return false, []string{fmt.Sprintf("method %s is not cacheable", res.Method)}
	}
	if !MethodCacheableByDefault(res.Method) && !explicitFreshness {
		return false, []string{fmt.Sprintf("method %s requires explicit freshness (max-age/s-maxage/Expires) to be cacheable", res.Method)}
	}

	if !StatusDefaultCacheable(res.StatusCode) && !explicitFreshness {
		return false, []string{fmt.Sprintf("status %d has no defined cache semantics and no explicit freshness was given", res.StatusCode)}
	}

	reasons := []string{fmt.Sprintf("status %d is cacheable by default or has explicit freshness", res.StatusCode)}
	if explicitFreshness {
		reasons = append(reasons, "explicit freshness present (max-age/s-maxage/Expires)")
	}
	return true, reasons
}

// conflictFindings flags directive combinations that are contradictory,
// redundant, or likely to confuse a cache operator.
func conflictFindings(cc CacheControl) []harnessx.Observation {
	var out []harnessx.Observation
	add := func(title, desc, severity string) {
		out = append(out, harnessx.Observation{Title: title, Description: desc, Metadata: map[string]string{checkbase.SeverityKey: severity}})
	}

	if cc.NoStore && (cc.MaxAge != nil || cc.SMaxAge != nil) {
		add("Conflicting Cache-Control directives", "no-store is combined with max-age/s-maxage; no-store takes precedence and the freshness directives are ignored by conforming caches", checkbase.SeverityLow)
	}
	if cc.Public && cc.Private {
		add("Conflicting Cache-Control directives", "both public and private are set; private takes precedence for shared caches, making public misleading", checkbase.SeverityLow)
	}
	if cc.NoCache && cc.NoStore {
		add("Redundant Cache-Control directives", "no-cache is redundant alongside no-store, which already forbids any storage", checkbase.SeverityInfo)
	}
	if cc.Private && cc.SMaxAge != nil {
		add("Confusing Cache-Control directives", "s-maxage only applies to shared caches, but private tells shared caches not to store the response at all — s-maxage has no effect here", checkbase.SeverityLow)
	}
	return out
}

func pragmaFinding(header http.Header, cc CacheControl) harnessx.Observation {
	if header.Get("Cache-Control") != "" {
		return harnessx.Observation{}
	}
	pragma := strings.ToLower(header.Get("Pragma"))
	if !strings.Contains(pragma, "no-cache") {
		return harnessx.Observation{}
	}
	return harnessx.Observation{
		Title:       "Legacy Pragma fallback in use",
		Description: "no Cache-Control header is present; caching behavior relies solely on the legacy HTTP/1.0 Pragma: no-cache header, which modern shared caches may ignore",
		Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityInfo},
	}
}

func parseVary(header string) []string {
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
