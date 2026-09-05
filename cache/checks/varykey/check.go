// Package varykey implements §4 of cache-detective: probing what varies
// the cache key. It tests the declared Vary header for correctness, and
// tests undeclared inputs (Accept-Encoding, Accept-Language, User-Agent,
// and a custom header) for whether they're actually keyed — i.e. whether
// two requests that differ only in that input get different cached
// responses.
//
// Every probe here issues extra requests to the live target beyond the
// single baseline request. It's read-only from the target's point of view
// (it never injects content a poisoned cache would later replay — that's
// §5/security's job) so it runs by default, but honors
// ProbeCtx.MaxAggressiveRequests as a hard cap on probe count per resource
// regardless of Aggressive.
package varykey

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// Def describes the cache-key & Vary analysis check.
var Def = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDVaryKey),
	Name:        "Cache Key & Vary Analysis",
	Description: "Probes what varies the cache key: declared Vary headers, and whether Accept-Encoding/Accept-Language/User-Agent/a custom header are actually keyed.",
	Tags:        []string{"vary", "cache-key"},
	DependsOn:   []string{string(checkbase.CheckIDDiscovery)},
}

// Check runs cache-key analysis against each discovered resource.
var Check = checkdef.NewResourceCheck(Def, run)

// Probe is one input dimension tested for cache-key inclusion.
type Probe struct {
	Dimension string // e.g. "accept-encoding", "accept-language", "user-agent", "custom-header"
	Declared  bool   // present in the response's declared Vary header
	Keyed     bool   // true when varying this input produced a different cached response
	Evidence  string
}

// Result is the cache-key analysis outcome for one resource.
type Result struct {
	DeclaredVary []string
	Probes       []Probe
}

var dimensions = []struct {
	name   string
	header http.Header
	// raw sends the probe through DoRaw instead of Do — needed for
	// "user-agent" since Probe.RoundTrip always overwrites that header.
	raw bool
}{
	{name: "accept-encoding", header: http.Header{"Accept-Encoding": {"br"}}},
	{name: "accept-language", header: http.Header{"Accept-Language": {"fr-FR"}}},
	{name: "user-agent", header: http.Header{"User-Agent": {"cache-detective-varykey-probe/1.0"}}, raw: true},
	{name: "custom-header", header: http.Header{"X-Cache-Detective-Probe": {"1"}}},
}

func run(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	pctx := target.Data.(*checkbase.ProbeCtx)

	baseReq, err := checkbase.NewRequest(ctx, resource.URL, pctx, nil)
	if err != nil {
		return harnessx.Result{}, err
	}
	base, err := checkbase.Do(ctx, pctx, baseReq)
	if err != nil {
		return harnessx.Result{}, err
	}

	res := Result{DeclaredVary: parseVary(base.Header.Get("Vary"))}

	budget := pctx.MaxAggressiveRequests
	for _, dim := range dimensions {
		if budget <= 0 {
			break
		}
		budget--

		req, err := checkbase.NewRequest(ctx, resource.URL, pctx, dim.header)
		if err != nil {
			continue
		}
		doFn := checkbase.Do
		if dim.raw {
			doFn = checkbase.DoRaw
		}
		ex, err := doFn(ctx, pctx, req)
		if err != nil {
			continue
		}

		declared := containsFold(res.DeclaredVary, dim.name)
		observedDiff := differs(base, ex)
		res.Probes = append(res.Probes, Probe{
			Dimension: dim.name,
			Declared:  declared,
			Keyed:     observedDiff,
			Evidence:  fmt.Sprintf("declared in Vary: %v, observed response change: %v", declared, observedDiff),
		})
	}

	obs := findingsFrom(res, resource.ID)
	return harnessx.Result{Data: res, Observations: obs}, nil
}

func findingsFrom(res Result, resourceID string) []harnessx.Observation {
	var obs []harnessx.Observation
	for _, p := range res.Probes {
		switch {
		case p.Keyed && !p.Declared:
			obs = append(obs, harnessx.Observation{
				CheckID:     checkbase.CheckIDVaryKey,
				ResourceID:  resourceID,
				Title:       fmt.Sprintf("Undeclared cache-key input: %s", p.Dimension),
				Description: fmt.Sprintf("varying %s changed the response, but it is not declared in Vary — a cache-poisoning surface if the value is attacker-controlled", p.Dimension),
				Evidence:    p.Evidence,
				Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityMedium},
			})
		case !p.Keyed && p.Declared:
			obs = append(obs, harnessx.Observation{
				CheckID:     checkbase.CheckIDVaryKey,
				ResourceID:  resourceID,
				Title:       fmt.Sprintf("Declared Vary dimension has no observed effect: %s", p.Dimension),
				Description: fmt.Sprintf("%s is declared in Vary, but varying it produced no observable difference — likely inflates cache fragmentation for no benefit", p.Dimension),
				Evidence:    p.Evidence,
				Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityInfo},
			})
		}
	}
	return obs
}

// differs reports whether two exchanges look like different cache entries:
// a different cdn.Detect raw cache-status value, or a different response
// body.
func differs(a, b checkbase.Exchange) bool {
	da, db := cdn.Detect(a.Header), cdn.Detect(b.Header)
	if da.RawValue != "" && db.RawValue != "" && da.RawValue != db.RawValue {
		return true
	}
	return string(a.Body) != string(b.Body)
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

func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}
