package livestate

import (
	"testing"
	"time"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/stretchr/testify/assert"
)

func age(n int) *int { return &n }

func TestAnalyze_FirstMissThenHit(t *testing.T) {
	samples := []Sample{
		{Detection: cdn.Detection{State: cdn.StateMiss}},
		{Detection: cdn.Detection{State: cdn.StateHit, Age: age(1)}},
		{Detection: cdn.Detection{State: cdn.StateHit, Age: age(3)}},
	}
	res := Analyze(samples)
	assert.True(t, res.FirstMissThenHit)
	assert.Equal(t, 2, res.HitCount)
	assert.Equal(t, 1, res.MissCount)
	assert.True(t, res.AgeIncreased)
	assert.False(t, res.TimingHeuristic)
}

func TestAnalyze_AllHits(t *testing.T) {
	samples := []Sample{
		{Detection: cdn.Detection{State: cdn.StateHit}},
		{Detection: cdn.Detection{State: cdn.StateHit}},
	}
	res := Analyze(samples)
	assert.False(t, res.FirstMissThenHit)
	assert.Equal(t, 2, res.HitCount)
}

func TestAnalyze_TimingHeuristicFallback_AgeOnly(t *testing.T) {
	samples := []Sample{
		{Detection: cdn.Detection{Age: age(5)}, Duration: 50 * time.Millisecond},
	}
	res := Analyze(samples)
	assert.True(t, res.TimingHeuristic)
	assert.Equal(t, cdn.StateHit, res.InferredState.State)
}

func TestAnalyze_TimingHeuristicFallback_LatencyDrop(t *testing.T) {
	samples := []Sample{
		{Detection: cdn.Detection{}, Duration: 200 * time.Millisecond},
		{Detection: cdn.Detection{}, Duration: 20 * time.Millisecond},
	}
	res := Analyze(samples)
	assert.True(t, res.TimingHeuristic)
	assert.Equal(t, cdn.StateHit, res.InferredState.State)
}

func TestAnalyze_TimingHeuristicFallback_NoSignal(t *testing.T) {
	samples := []Sample{
		{Detection: cdn.Detection{}, Duration: 50 * time.Millisecond},
		{Detection: cdn.Detection{}, Duration: 48 * time.Millisecond},
	}
	res := Analyze(samples)
	assert.True(t, res.TimingHeuristic)
	assert.Equal(t, cdn.StateUnknown, res.InferredState.State)
}

func TestAnalyze_Empty(t *testing.T) {
	res := Analyze(nil)
	assert.Empty(t, res.Samples)
}
