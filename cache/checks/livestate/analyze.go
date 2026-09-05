// Package livestate implements §2 of cache-detective: determining a
// response's live cache state (HIT/MISS/STALE/EXPIRED/BYPASS) from
// known CDN headers, with a timing/Age-based heuristic fallback when no
// explicit cache-status header is present, plus multi-request probing to
// observe a HIT ratio and the first-miss-then-hit pattern.
package livestate

import (
	"net/http"
	"time"

	"github.com/cerberauth/cache-detective/cache/cdn"
)

// Sample is one probe request's outcome, reduced to what the live-state
// analysis needs.
type Sample struct {
	Detection  cdn.Detection
	Duration   time.Duration
	StatusCode int
}

// AnalysisResult is the live cache-state verdict for one resource, derived
// from N samples (see ProbeCtx.RequestCount).
type AnalysisResult struct {
	Samples []Sample

	// FinalState is the state reported by the last sample — the most
	// representative single verdict when a caller wants one answer.
	FinalState cdn.Detection

	// HitCount / MissCount tally samples whose Detection.State was HIT or
	// MISS (STALE/EXPIRED/BYPASS/UNKNOWN are excluded from the ratio).
	HitCount  int
	MissCount int

	// FirstMissThenHit is true when the first sample MISSed and a later
	// sample HIT — the textbook cold-cache-then-warm pattern.
	FirstMissThenHit bool

	// AgeIncreased is true when Age was observed increasing across
	// consecutive samples that were both HITs — evidence the same cached
	// object was served repeatedly rather than being refreshed each time.
	AgeIncreased bool

	// TimingHeuristic is set when no CDN emitted an explicit cache-status
	// header and the verdict below is inferred from timing/Age instead.
	TimingHeuristic bool
	// InferredState is the heuristic fallback's best guess, only
	// meaningful when TimingHeuristic is true.
	InferredState cdn.Detection
}

// Analyze reduces a sequence of samples (from N probe requests to the same
// resource, see ProbeCtx.RequestCount) to an AnalysisResult.
func Analyze(samples []Sample) AnalysisResult {
	res := AnalysisResult{Samples: samples}
	if len(samples) == 0 {
		return res
	}
	res.FinalState = samples[len(samples)-1].Detection

	explicit := false
	for _, s := range samples {
		switch s.Detection.State {
		case cdn.StateHit:
			res.HitCount++
			explicit = true
		case cdn.StateMiss:
			res.MissCount++
			explicit = true
		case cdn.StateStale, cdn.StateExpired, cdn.StateBypass, cdn.StateDynamic:
			explicit = true
		}
	}

	seenMiss := false
	var lastHitAge *int
	for _, s := range samples {
		switch s.Detection.State {
		case cdn.StateMiss:
			seenMiss = true
		case cdn.StateHit:
			if seenMiss {
				res.FirstMissThenHit = true
			}
			if lastHitAge != nil && s.Detection.Age != nil && *s.Detection.Age > *lastHitAge {
				res.AgeIncreased = true
			}
			lastHitAge = s.Detection.Age
		}
	}

	if !explicit {
		res.TimingHeuristic = true
		res.InferredState = inferFromTiming(samples)
	}

	return res
}

// inferFromTiming is the fallback used when no CDN header gave an explicit
// verdict: repeated requests are compared by latency and by whether an Age
// header is present/increasing. A cached response is typically served
// faster on repeat and/or carries a non-decreasing Age; this is inherently
// a heuristic; TimingHeuristic on the result signals that to the caller.
func inferFromTiming(samples []Sample) cdn.Detection {
	if len(samples) == 1 {
		if samples[0].Detection.Age != nil {
			return cdn.Detection{State: cdn.StateHit, Source: "Age header present", RawValue: "single sample"}
		}
		return cdn.Detection{State: cdn.StateUnknown}
	}

	first := samples[0]
	last := samples[len(samples)-1]

	if last.Detection.Age != nil && (first.Detection.Age == nil || *last.Detection.Age >= *first.Detection.Age) {
		return cdn.Detection{State: cdn.StateHit, Source: "Age header non-decreasing across samples", RawValue: "timing heuristic"}
	}

	// Repeat requests answered meaningfully faster than the first suggest a
	// cache is serving them, even with no explicit header signal.
	if last.Duration > 0 && first.Duration > 0 && last.Duration*2 < first.Duration {
		return cdn.Detection{State: cdn.StateHit, Source: "latency dropped on repeat request", RawValue: "timing heuristic"}
	}

	return cdn.Detection{State: cdn.StateUnknown}
}

// DetectFromHeader is a thin re-export of cdn.Detect, so callers building
// Samples don't need to import the cdn package directly.
func DetectFromHeader(h http.Header) cdn.Detection {
	return cdn.Detect(h)
}
