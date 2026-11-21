// Package cache wires together every check package (cacheability,
// livestate, fingerprint, varykey, security, consistency, staleserving) into the
// registered harnessx.Engine check list: BuildChecks/CheckDefs describe
// the fixed check registry, and ScanAll drives one harnessx.Engine.Run.
//
// cache-detective needs concurrent multi-URL probing (a single scan, list
// file, sitemap, or crawl) — so every check here is ScopePerResource, fed
// by checkbase.DiscoveryCheck's resource list, and the harnessx engine's
// existing per-resource concurrency (Check.Concurrency /
// WithMaxResourceConcurrency) does the fan-out instead of a bespoke
// worker pool.
package cache

import (
	"context"
	"fmt"
	"slices"

	"github.com/cerberauth/harnessx"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
	"github.com/cerberauth/cache-detective/cache/checks/consistency"
	"github.com/cerberauth/cache-detective/cache/checks/disclosure"
	"github.com/cerberauth/cache-detective/cache/checks/fingerprint"
	"github.com/cerberauth/cache-detective/cache/checks/livestate"
	"github.com/cerberauth/cache-detective/cache/checks/security"
	"github.com/cerberauth/cache-detective/cache/checks/smuggling"
	"github.com/cerberauth/cache-detective/cache/checks/staleserving"
	"github.com/cerberauth/cache-detective/cache/checks/varykey"
)

// ProbeCtx re-exports checkbase.ProbeCtx so callers only need to import
// this top-level package for the common case.
type ProbeCtx = checkbase.ProbeCtx

// ResourceSpec re-exports checkbase.ResourceSpec.
type ResourceSpec = checkbase.ResourceSpec

// BuildChecks returns the full cache-detective check registry (discovery +
// every analysis/security check) and their metadata, in dependency order.
// Exported so callers embedding these checks in their own harnessx.Engine
// build the exact same check list ScanAll uses.
func BuildChecks() ([]harnessx.Check, map[harnessx.CheckID]checkbase.CheckDef) {
	checks := []harnessx.Check{
		checkbase.DiscoveryCheck,
		cacheability.Check,
		cacheability.AuthCheck,
		cacheability.SessionCheck,
		livestate.Check,
		disclosure.Check,
		fingerprint.Check,
		varykey.Check,
		consistency.Check,
		staleserving.Check,
		security.UnkeyedHeaderCheck,
		security.CacheDeceptionCheck,
		security.ErrorCachingCheck,
		security.ResponseSplittingCheck,
		security.CPDoSCheck,
		security.DelimiterMapperCheck,
		security.DelimiterDeceptionCheck,
		security.EntanglementCheck,
		security.NormalizationDeceptionCheck,
		security.KeyCollisionCheck,
		security.KeyExplosionCheck,
		smuggling.Check,
		security.UnkeyedImpactCheck,
		security.URLParserDiscrepancyCheck,
	}

	defs := map[harnessx.CheckID]checkbase.CheckDef{
		checkbase.CheckIDCacheability:           cacheability.Def,
		checkbase.CheckIDAuthCacheable:          cacheability.AuthDef,
		checkbase.CheckIDSessionCacheable:       cacheability.SessionDef,
		checkbase.CheckIDLiveState:              livestate.Def,
		checkbase.CheckIDInfoDisclosure:         disclosure.Def,
		checkbase.CheckIDFingerprint:            fingerprint.Def,
		checkbase.CheckIDVaryKey:                varykey.Def,
		checkbase.CheckIDConsistency:            consistency.Def,
		checkbase.CheckIDStaleServing:           staleserving.Def,
		checkbase.CheckIDUnkeyedHeader:          security.UnkeyedHeaderDef,
		checkbase.CheckIDCacheDeception:         security.CacheDeceptionDef,
		checkbase.CheckIDErrorCaching:           security.ErrorCachingDef,
		checkbase.CheckIDResponseSplitting:      security.ResponseSplittingDef,
		checkbase.CheckIDCPDoS:                  security.CPDoSDef,
		checkbase.CheckIDDelimiterMapper:        security.DelimiterMapperDef,
		checkbase.CheckIDDelimiterDeception:     security.DelimiterDeceptionDef,
		checkbase.CheckIDEntanglement:           security.EntanglementDef,
		checkbase.CheckIDNormalizationDeception: security.NormalizationDeceptionDef,
		checkbase.CheckIDKeyCollision:           security.KeyCollisionDef,
		checkbase.CheckIDKeyExplosion:           security.KeyExplosionDef,
		checkbase.CheckIDSmuggling:              smuggling.Def,
		checkbase.CheckIDUnkeyedImpact:          security.UnkeyedImpactDef,
		checkbase.CheckIDURLParserDiscrepancy:   security.URLParserDiscrepancyDef,
	}
	for i := range checks {
		checks[i] = tagMode(withResourceRequest(checks[i]))
	}
	for id, def := range defs {
		def.Tags = append(slices.Clone(def.Tags), modeTag(harnessx.CheckID(def.ID)))
		defs[id] = def
	}
	return checks, defs
}

// Tags telling a read-only check from one that can pollute a shared cache,
// so a host selects either set by tag instead of by ID.
const (
	TagPassive    = "passive"
	TagAggressive = "aggressive"
)

// aggressiveChecks are the checks that send cache-poisoning/deception probes
// and so only run under ProbeCtx.Aggressive (smuggling additionally needs
// ProbeCtx.EnableSmuggling). Every other check is read-only.
var aggressiveChecks = map[harnessx.CheckID]bool{
	checkbase.CheckIDUnkeyedHeader:          true,
	checkbase.CheckIDCacheDeception:         true,
	checkbase.CheckIDErrorCaching:           true,
	checkbase.CheckIDResponseSplitting:      true,
	checkbase.CheckIDCPDoS:                  true,
	checkbase.CheckIDDelimiterMapper:        true,
	checkbase.CheckIDDelimiterDeception:     true,
	checkbase.CheckIDEntanglement:           true,
	checkbase.CheckIDNormalizationDeception: true,
	checkbase.CheckIDKeyCollision:           true,
	checkbase.CheckIDKeyExplosion:           true,
	checkbase.CheckIDSmuggling:              true,
	checkbase.CheckIDUnkeyedImpact:          true,
	checkbase.CheckIDURLParserDiscrepancy:   true,
}

func modeTag(id harnessx.CheckID) string {
	if aggressiveChecks[id] {
		return TagAggressive
	}
	return TagPassive
}

func tagMode(c harnessx.Check) harnessx.Check {
	if c.Internal {
		return c
	}
	c.Tags = append(slices.Clone(c.Tags), modeTag(c.ID))
	return c
}

// withResourceRequest makes a per-resource check probe with the request shape
// of the resource it runs on (see checkbase.ResourceRequest) instead of only
// the scan-wide one, so a host engine supplying its own resources controls
// each resource's method, headers, cookies and body.
func withResourceRequest(c harnessx.Check) harnessx.Check {
	if run := c.RunResource; run != nil {
		c.RunResource = func(ctx context.Context, target harnessx.Target, res harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
			return run(ctx, forResource(target, res), res, store)
		}
	}
	if run := c.RunResourceVariant; run != nil {
		c.RunResourceVariant = func(ctx context.Context, target harnessx.Target, res harnessx.Resource, variant string, store harnessx.ResultStore) (harnessx.Result, error) {
			return run(ctx, forResource(target, res), res, variant, store)
		}
	}
	return c
}

func forResource(target harnessx.Target, res harnessx.Resource) harnessx.Target {
	if pctx, ok := target.Data.(*checkbase.ProbeCtx); ok {
		target.Data = checkbase.ForResource(pctx, res)
	}
	return target
}

// legacyCheckIDs maps the un-prefixed check IDs used before the pack
// contract to their `cache.` IDs.
var legacyCheckIDs = map[string]harnessx.CheckID{
	"discovery":                checkbase.CheckIDDiscovery,
	"cacheability":             checkbase.CheckIDCacheability,
	"live-state":               checkbase.CheckIDLiveState,
	"fingerprint":              checkbase.CheckIDFingerprint,
	"vary-key":                 checkbase.CheckIDVaryKey,
	"unkeyed-header-injection": checkbase.CheckIDUnkeyedHeader,
	"cache-deception":          checkbase.CheckIDCacheDeception,
	"error-caching":            checkbase.CheckIDErrorCaching,
	"response-splitting":       checkbase.CheckIDResponseSplitting,
	"cpdos":                    checkbase.CheckIDCPDoS,
	"delimiter-mapper":         checkbase.CheckIDDelimiterMapper,
	"cache-entanglement":       checkbase.CheckIDEntanglement,
	"normalization-deception":  checkbase.CheckIDNormalizationDeception,
	"key-collision":            checkbase.CheckIDKeyCollision,
	"key-explosion":            checkbase.CheckIDKeyExplosion,
	"consistency":              checkbase.CheckIDConsistency,
	"stale-serving":            checkbase.CheckIDStaleServing,
	"authenticated-cacheable":  checkbase.CheckIDAuthCacheable,
	"session-cacheable":        checkbase.CheckIDSessionCacheable,
}

// ResolveCheckID returns the pack check ID id names: a `cache.` ID as is, or
// a legacy un-prefixed ID (`authenticated-cacheable`) mapped to its `cache.`
// ID. It reports false for an ID that names no check.
func ResolveCheckID(id string) (harnessx.CheckID, bool) {
	if cid, ok := legacyCheckIDs[id]; ok {
		return cid, true
	}
	cid := harnessx.CheckID(id)
	_, defs := BuildChecks()
	_, ok := defs[cid]
	return cid, ok
}

// NewProbeCtx returns the pack context every cache-detective check reads from
// Target.Data: opts with defaults applied.
func NewProbeCtx(opts ProbeCtx) *ProbeCtx {
	pctx := opts.WithDefaults()
	return &pctx
}

// Checks returns the cache-detective check pack: every check with a `cache.`
// ID, resource discovery marked internal and findings reported as
// Observations, for embedding in another harnessx engine with harnessx/embed.
// Each check reads a *ProbeCtx built by NewProbeCtx from Target.Data.
func Checks() []harnessx.Check {
	checks, _ := BuildChecks()
	return checks
}

// CheckDefs returns per-check metadata (name, CVSS, CWE, OWASP, link,
// description) keyed by CheckID, for callers that need to enrich results
// outside of ScanAll (e.g. a harnessx.Reporter).
func CheckDefs() map[harnessx.CheckID]checkbase.CheckDef {
	_, defs := BuildChecks()
	return defs
}

// ScanOptions configures a full cache-detective scan.
type ScanOptions struct {
	// ProbeCtx carries every per-scan setting: HTTP client, custom
	// headers/cookies/auth, request count/interval, aggressive-mode gate,
	// and the resolved resource list (see the cache/crawl package).
	ProbeCtx checkbase.ProbeCtx

	// Reporters receive live progress/results, e.g. harnessreport.New for
	// building a reportx report, or an OTel reporter for telemetry.
	Reporters []harnessx.Reporter

	// RunOptions further restricts which registered checks run, e.g.
	// harnessx.WithExclude(checkbase.CheckIDFingerprint) to skip DNS
	// lookups, or an aggressive-mode-only subset via WithOnly.
	RunOptions []harnessx.RunOption

	// MaxConcurrency / MaxResourceConcurrency bound the engine's
	// parallelism across resources (§7: concurrent multi-URL probing with
	// configurable rate limiting).
	MaxConcurrency         int
	MaxResourceConcurrency int
}

// ScanAll registers every check via BuildChecks and runs them against the
// resources in opts.ProbeCtx.Resources, returning the harnessx.ScanSummary.
func ScanAll(ctx context.Context, target string, opts ScanOptions) (harnessx.ScanSummary, error) {
	pctx := NewProbeCtx(opts.ProbeCtx)

	var engineOpts []harnessx.Option
	if len(opts.Reporters) > 0 {
		engineOpts = append(engineOpts, harnessx.WithReporters(opts.Reporters...))
	}
	if opts.MaxConcurrency > 0 {
		engineOpts = append(engineOpts, harnessx.WithMaxConcurrency(opts.MaxConcurrency))
	}
	if opts.MaxResourceConcurrency > 0 {
		engineOpts = append(engineOpts, harnessx.WithMaxResourceConcurrency(opts.MaxResourceConcurrency))
	}

	engine := harnessx.New(engineOpts...)
	if err := engine.Register(Checks()...); err != nil {
		return harnessx.ScanSummary{}, fmt.Errorf("cache: registering checks: %w", err)
	}

	return engine.Run(ctx, harnessx.Target{URL: target, Data: pctx}, opts.RunOptions...)
}
