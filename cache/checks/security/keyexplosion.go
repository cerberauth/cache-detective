package security

import (
	"context"
	"fmt"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// --- Cache-key explosion (§5) ----------------------------------------------

var KeyExplosionDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDKeyExplosion),
	Name:        "Cache-Key Explosion",
	Description: "Requests the resource with many distinct random values for one query parameter and checks whether every value is cached as its own entry (a MISS each time, a HIT on repeat) with no cap. An attacker can then fill the cache with junk entries and force an origin request per unique value, defeating the cache. Needs --max-aggressive-requests of at least 21 and a readable cache-status header; with fewer requests there is no way to tell \"no cap\" from \"a cap higher than the sample\".",
	Tags:        []string{securityTag, cacheKeyTag, "denial-of-service"},
	// Same ordering rationale as EntanglementDef.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDCPDoS)},
	CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
	CVSSScore:  5.3,
	CWEID:      "CWE-400",
}

var KeyExplosionCheck = checkdef.NewResourceCheck(KeyExplosionDef, runKeyExplosion)

// keyExplosionProbes is how many distinct values are tried. It has to exceed
// the per-path entry cap a hardened cache might enforce for a "still
// unbounded after this many" verdict to mean anything; 20 clears the cap of
// 16 the reference challenge uses, while staying a modest burst against a
// live target. The check needs one more request than this to confirm the
// first entry was actually stored.
const keyExplosionProbes = 20

// keyExplosionFallbackParam is varied when the resource has no query
// parameter of its own to vary.
const keyExplosionFallbackParam = "cd_key"

func runKeyExplosion(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)
	if pctx.MaxAggressiveRequests < keyExplosionProbes+1 {
		return harnessx.Result{}, nil
	}

	// Vary a parameter the resource already takes when there is one: a cache
	// that keys on specific parameters (rather than the whole query string)
	// only sees values that change one of those.
	param := keyExplosionFallbackParam
	if names := queryParamNames(resource.URL); len(names) > 0 {
		param = names[0]
	}

	var firstURL string
	for i := 0; i < keyExplosionProbes; i++ {
		probeURL := withExtraQueryParam(resource.URL, param, randomPathToken())
		ex, err := fetchExchange(ctx, pctx, probeURL)
		if err != nil {
			return harnessx.Result{}, nil
		}
		// Anything but a MISS ends it: a HIT means a shared bucket / cap (or a
		// parameter the cache doesn't key on at all), and BYPASS / no
		// readable status means there's no cache state to count entries by.
		if cdn.Detect(ex.Header).State != cdn.StateMiss {
			return harnessx.Result{}, nil
		}
		if i == 0 {
			firstURL = probeURL
		}
	}

	// All of that is also what an uncacheable response looks like. The first
	// value being a HIT on repeat shows the entries really were stored.
	repeat, err := fetchExchange(ctx, pctx, firstURL)
	if err != nil || cdn.Detect(repeat.Header).State != cdn.StateHit {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Observations: []harnessx.Observation{{
		CheckID:     checkbase.CheckIDKeyExplosion,
		ResourceID:  resource.ID,
		Title:       "Unbounded cache-key cardinality",
		Description: fmt.Sprintf("%d requests with a different random value for the %q query parameter each created a separate cache entry (a MISS every time, and a HIT on repeating the first) — no cap on distinct entries was observed. Most caches key on the full query string by design, so this is an inherent exposure rather than a defect in itself; an attacker can still exhaust cache storage and force an origin request per unique value. Mitigate with rate limiting, query-parameter allowlisting or normalization at the edge", keyExplosionProbes, param),
		Evidence:    fmt.Sprintf("%d/%d distinct %s values were cache MISSes", keyExplosionProbes, keyExplosionProbes, param),
		Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityLow},
	}}}, nil
}
