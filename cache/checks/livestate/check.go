package livestate

import (
	"context"
	"fmt"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
)

// Def describes the live cache-state detection check.
var Def = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDLiveState),
	Name:        "Live Cache State Detection",
	Description: "Issues N probe requests per resource and classifies each response's live cache state (HIT/MISS/STALE/EXPIRED/BYPASS) from known CDN headers, falling back to a timing/Age heuristic when no explicit header is present.",
	Tags:        []string{"live-state", "cdn"},
	DependsOn:   []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDCacheability)},
}

// Check runs the live cache-state probe against each discovered resource.
var Check = checkdef.NewResourceCheck(Def, run)

func run(ctx context.Context, target harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	pctx := target.Data.(*checkbase.ProbeCtx)

	samples := make([]Sample, 0, pctx.RequestCount)
	for i := 0; i < max(pctx.RequestCount, 1); i++ {
		if i > 0 && pctx.RequestInterval > 0 {
			select {
			case <-ctx.Done():
				return harnessx.Result{}, ctx.Err()
			case <-time.After(pctx.RequestInterval):
			}
		}
		req, err := checkbase.NewRequest(ctx, resource.URL, pctx, nil)
		if err != nil {
			return harnessx.Result{}, err
		}
		ex, err := checkbase.Do(ctx, pctx, req)
		if err != nil {
			return harnessx.Result{}, err
		}
		samples = append(samples, Sample{
			Detection:  DetectFromHeader(ex.Header),
			Duration:   ex.Duration,
			StatusCode: ex.StatusCode,
		})
	}

	analysis := Analyze(samples)

	var obs []harnessx.Observation
	if analysis.TimingHeuristic {
		obs = append(obs, harnessx.Observation{
			Title:       "No explicit cache-status header",
			Description: fmt.Sprintf("no known CDN cache-status header was present; live state was inferred from timing/Age as %s (best-effort)", analysis.InferredState.State),
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityInfo},
		})
	}

	if dep, ok := store.GetForResource(checkbase.CheckIDCacheability, resource.ID); ok && !dep.Skipped {
		if declared, ok := harnessx.DataAs[cacheability.AnalysisResult](dep); ok {
			if declared.Cacheable && !analysis.TimingHeuristic && analysis.HitCount == 0 && analysis.MissCount > 0 {
				obs = append(obs, harnessx.Observation{
					Title:       "Cacheable response is not actually being cached",
					Description: "the response declares itself cacheable (Cache-Control/Expires/status), but every observed sample MISSed — the CDN/reverse-proxy in front of the origin isn't caching it",
					Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityLow},
				})
			}
			if !declared.Cacheable && analysis.HitCount > 0 {
				obs = append(obs, harnessx.Observation{
					Title:       "Non-cacheable response is being served from cache",
					Description: "the response is not supposed to be cacheable per its headers, but at least one sample was served as a cache HIT — check for stale Cache-Control on an edge config that doesn't match the origin",
					Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityMedium},
				})
			}
		}
	}

	for i := range obs {
		obs[i].CheckID = checkbase.CheckIDLiveState
		obs[i].ResourceID = resource.ID
	}

	return harnessx.Result{Data: analysis, Observations: obs}, nil
}
