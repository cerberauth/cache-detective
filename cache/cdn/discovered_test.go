package cdn_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/cdn"
)

func boolPtr(b bool) *bool { return &b }

func TestQuirkStore_RecordAndLookup(t *testing.T) {
	store := cdn.NewQuirkStore()

	_, ok := store.Lookup("https://example.test")
	assert.False(t, ok, "an unprobed origin has no record")

	store.Record(cdn.TargetQuirks{
		Origin:                           "https://example.test",
		Delimiters:                       []cdn.DelimiterDiscrepancy{{Delimiter: ";", OriginOnly: true, Cacheable: true}},
		OriginNormalizesEncodedTraversal: boolPtr(true),
	})

	got, ok := store.Lookup("https://example.test")
	require.True(t, ok)
	require.Len(t, got.Delimiters, 1)
	assert.Equal(t, ";", got.Delimiters[0].Delimiter)
	require.NotNil(t, got.OriginNormalizesEncodedTraversal)
	assert.True(t, *got.OriginNormalizesEncodedTraversal)
	assert.Nil(t, got.OriginNormalizesTraversal)
}

// TestQuirkStore_MergesAcrossResources proves a second Record for the same
// origin unions in new delimiters (deduplicating existing ones) and fills in a
// normalization flag left unset by the first — the "accumulate across the
// origin's resources" behavior.
func TestQuirkStore_MergesAcrossResources(t *testing.T) {
	store := cdn.NewQuirkStore()

	store.Record(cdn.TargetQuirks{
		Origin:     "https://example.test",
		Delimiters: []cdn.DelimiterDiscrepancy{{Delimiter: ";", OriginOnly: true}},
	})
	store.Record(cdn.TargetQuirks{
		Origin: "https://example.test",
		Delimiters: []cdn.DelimiterDiscrepancy{
			{Delimiter: ";", OriginOnly: true}, // duplicate — must not double
			{Delimiter: "$", OriginOnly: true},
		},
		OriginNormalizesTraversal: boolPtr(false),
	})

	got, ok := store.Lookup("https://example.test")
	require.True(t, ok)
	require.Len(t, got.Delimiters, 2)
	assert.Equal(t, ";", got.Delimiters[0].Delimiter)
	assert.Equal(t, "$", got.Delimiters[1].Delimiter)
	require.NotNil(t, got.OriginNormalizesTraversal)
	assert.False(t, *got.OriginNormalizesTraversal)
}

func TestQuirkStore_LookupReturnsCopy(t *testing.T) {
	store := cdn.NewQuirkStore()
	store.Record(cdn.TargetQuirks{
		Origin:     "https://example.test",
		Delimiters: []cdn.DelimiterDiscrepancy{{Delimiter: ";", OriginOnly: true}},
	})

	got, _ := store.Lookup("https://example.test")
	got.Delimiters[0].Delimiter = "mutated"
	got.Delimiters = append(got.Delimiters, cdn.DelimiterDiscrepancy{Delimiter: "x"})

	again, _ := store.Lookup("https://example.test")
	require.Len(t, again.Delimiters, 1)
	assert.Equal(t, ";", again.Delimiters[0].Delimiter, "mutating a looked-up copy must not touch the store")
}

func TestQuirkStore_RecordEmptyOriginNoop(t *testing.T) {
	store := cdn.NewQuirkStore()
	store.Record(cdn.TargetQuirks{Origin: ""})
	_, ok := store.Lookup("")
	assert.False(t, ok)
}
