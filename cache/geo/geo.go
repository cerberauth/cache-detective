// Package geo defines the pluggable interface for §8 of cache-detective:
// multi-region probing to detect per-PoP cache inconsistency. No real
// geo-distributed backend ships in v1 (that needs either a fleet of
// proxy/VPN egress points or a paid third-party probe service — out of
// scope for this pass) — this package defines the contract now, backed by
// a NoopProvider, so a real backend drops in later without reshaping any
// check that wants per-region results.
package geo

import (
	"context"
	"net/http"
	"time"
)

// Region identifies one geo-distributed probing location, e.g.
// "aws-us-east-1" or a third-party service's region code. It's an opaque
// string so a Provider can define its own naming.
type Region string

// Probe is one region's outcome for a single request.
type Probe struct {
	Region     Region
	StatusCode int
	Header     http.Header
	Duration   time.Duration
	Err        error
}

// Provider issues a request from one or more geo-distributed vantage
// points. Implementations wrap whatever backend does the actual
// distributed dispatch — a fleet of regional proxies, a VPN broker, or a
// third-party geo-probe API.
type Provider interface {
	// Regions lists the vantage points this provider can probe from.
	Regions(ctx context.Context) ([]Region, error)

	// ProbeFrom issues req from each of the given regions (or every region
	// Regions() returns, if regions is empty) and returns one Probe per
	// region attempted.
	ProbeFrom(ctx context.Context, req *http.Request, regions []Region) ([]Probe, error)
}

// NoopProvider is a Provider with no regions — the default when no real
// geo-probing backend is configured. Every call succeeds trivially with an
// empty result, so callers can unconditionally wire a Provider without a
// nil check, and a check built against this interface degrades to "geo
// probing unavailable" rather than failing.
type NoopProvider struct{}

func (NoopProvider) Regions(context.Context) ([]Region, error) { return nil, nil }

func (NoopProvider) ProbeFrom(context.Context, *http.Request, []Region) ([]Probe, error) {
	return nil, nil
}

// Inconsistency describes a per-PoP cache disagreement detected across
// regions — e.g. one region HIT-ing while another MISSes for the same
// resource within a window where both should have warmed.
type Inconsistency struct {
	ResourceID string
	Regions    []Region
	Detail     string
}

// CompareCacheState is the analysis step a real Provider's ProbeFrom
// results feed into: given the per-region Probes for one resource, it
// flags a disagreement in cache-status headers across regions. It's a
// free function (not tied to a harnessx Check) so it can be reused however
// a future check chooses to shape its own request/response cycle around
// multi-region probing.
func CompareCacheState(resourceID string, probes []Probe, cacheStatusHeader string) *Inconsistency {
	seen := map[string]Region{}
	for _, p := range probes {
		if p.Err != nil || p.Header == nil {
			continue
		}
		v := p.Header.Get(cacheStatusHeader)
		if v == "" {
			continue
		}
		if other, ok := firstDifferent(seen, v); ok {
			return &Inconsistency{
				ResourceID: resourceID,
				Regions:    []Region{other, p.Region},
				Detail:     "cache-status differs across regions for the same resource",
			}
		}
		seen[v] = p.Region
	}
	return nil
}

func firstDifferent(seen map[string]Region, value string) (Region, bool) {
	for v, region := range seen {
		if v != value {
			return region, true
		}
	}
	return "", false
}
