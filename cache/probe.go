// Package cache wires together every check package (cacheability,
// livestate, fingerprint, varykey, security, consistency) into the
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

	"github.com/cerberauth/harnessx"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
	"github.com/cerberauth/cache-detective/cache/checks/consistency"
	"github.com/cerberauth/cache-detective/cache/checks/fingerprint"
	"github.com/cerberauth/cache-detective/cache/checks/livestate"
	"github.com/cerberauth/cache-detective/cache/checks/security"
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
		livestate.Check,
		fingerprint.Check,
		varykey.Check,
		consistency.Check,
		security.UnkeyedHeaderCheck,
		security.CacheDeceptionCheck,
		security.ErrorCachingCheck,
		security.ResponseSplittingCheck,
	}

	defs := map[harnessx.CheckID]checkbase.CheckDef{
		checkbase.CheckIDCacheability:      cacheability.Def,
		checkbase.CheckIDAuthCacheable:     cacheability.AuthDef,
		checkbase.CheckIDLiveState:         livestate.Def,
		checkbase.CheckIDFingerprint:       fingerprint.Def,
		checkbase.CheckIDVaryKey:           varykey.Def,
		checkbase.CheckIDConsistency:       consistency.Def,
		checkbase.CheckIDUnkeyedHeader:     security.UnkeyedHeaderDef,
		checkbase.CheckIDCacheDeception:    security.CacheDeceptionDef,
		checkbase.CheckIDErrorCaching:      security.ErrorCachingDef,
		checkbase.CheckIDResponseSplitting: security.ResponseSplittingDef,
	}
	return checks, defs
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
	pctx := opts.ProbeCtx.WithDefaults()

	checks, _ := BuildChecks()

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
	if err := engine.Register(checks...); err != nil {
		return harnessx.ScanSummary{}, fmt.Errorf("cache: registering checks: %w", err)
	}

	return engine.Run(ctx, harnessx.Target{URL: target, Data: &pctx}, opts.RunOptions...)
}
