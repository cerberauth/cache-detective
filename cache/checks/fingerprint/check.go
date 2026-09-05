// Package fingerprint implements §3 of cache-detective: identifying the
// fronting CDN/reverse-proxy via CNAME chain resolution, Server/Via header
// matching, and multi-tier cache detection. IP range (ASN/CIDR) matching is
// intentionally not implemented in v1 — see Result.IPRangeLookupAvailable —
// since it needs a maintained, licensable ASN/CIDR dataset; the field and
// the best-effort contract are defined now so a real backend can be
// dropped in later without reshaping this check.
package fingerprint

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/livestate"
)

// Def describes the CDN/proxy fingerprinting check.
var Def = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDFingerprint),
	Name:        "CDN/Proxy Fingerprinting",
	Description: "Identifies the fronting CDN/reverse-proxy via CNAME chain resolution and Server/Via header matching, and flags multi-tier caching (edge + shield/regional layer) evidence.",
	Tags:        []string{"fingerprint", "cdn"},
	DependsOn:   []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDLiveState)},
}

// Check runs CDN fingerprinting against each discovered resource.
var Check = checkdef.NewResourceCheck(Def, run)

// Result is the fingerprinting outcome for one resource.
type Result struct {
	CDN                    string
	Source                 string // "server-header" | "cname"
	CNAMEChain             []string
	MultiTier              bool
	TierEvidence           []string
	IPRangeLookupAvailable bool // always false in v1; see package doc
}

// CNAMEResolver resolves a hostname's CNAME chain, most specific first.
// Exposed as an interface (rather than hardcoding net.LookupCNAME) so tests
// can substitute a fake resolver.
type CNAMEResolver interface {
	LookupCNAME(ctx context.Context, host string) ([]string, error)
}

// DefaultResolver resolves CNAMEs via the standard library resolver,
// following the chain until it stops changing or hits a lookup error.
type DefaultResolver struct{}

func (DefaultResolver) LookupCNAME(ctx context.Context, host string) ([]string, error) {
	var chain []string
	seen := map[string]bool{}
	current := host
	resolver := net.DefaultResolver
	for i := 0; i < 10; i++ {
		cname, err := resolver.LookupCNAME(ctx, current)
		if err != nil || cname == "" || seen[cname] {
			break
		}
		chain = append(chain, cname)
		seen[cname] = true
		if cname == current+"." {
			break
		}
		current = cname
	}
	return chain, nil
}

// Resolver is package-level so callers (and tests) can swap it out; it
// defaults to real DNS lookups.
var Resolver CNAMEResolver = DefaultResolver{}

func run(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	// Reuse the response headers already captured by live-state instead of
	// issuing another request purely for a Server/Via header read.
	res := Result{}
	if r, ok := store.GetForResource(checkbase.CheckIDLiveState, resource.ID); ok && !r.Skipped {
		if analysis, ok := harnessx.DataAs[livestate.AnalysisResult](r); ok {
			det := analysis.FinalState
			res.CDN = det.CDN
			if det.CDN != "" {
				res.Source = "server-header"
			}
			res.TierEvidence = det.MultiTierEvidence
			res.MultiTier = len(det.MultiTierEvidence) > 0
		}
	}

	if host := hostOf(resource.URL); host != "" && Resolver != nil {
		chain, err := Resolver.LookupCNAME(ctx, host)
		if err == nil {
			res.CNAMEChain = chain
			if res.CDN == "" {
				if sig, ok := cdn.MatchCNAME(chain); ok {
					res.CDN = sig.Name
					res.Source = "cname"
				}
			}
		}
	}

	var obs []harnessx.Observation
	if res.MultiTier {
		obs = append(obs, harnessx.Observation{
			CheckID:     checkbase.CheckIDFingerprint,
			ResourceID:  resource.ID,
			Title:       "Multi-tier caching detected",
			Description: fmt.Sprintf("evidence of more than one cache tier (edge + shield/regional): %v", res.TierEvidence),
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityInfo},
		})
	}

	return harnessx.Result{Data: res, Observations: obs}, nil
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
