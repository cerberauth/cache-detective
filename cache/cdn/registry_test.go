package cdn_test

import (
	"strings"
	"testing"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/stretchr/testify/assert"
)

// TestRegistry_DataIntegrity guards the shape of Registry itself, not any
// one entry's accuracy — this table is meant to grow via community PRs (see
// the "Adding or extending a CDN entry" contribution guide), so it's worth
// catching malformed entries (a typo'd extension, a duplicate name, an
// apex domain that won't match MatchCNAME's suffix comparison) mechanically
// rather than only in review.
func TestRegistry_DataIntegrity(t *testing.T) {
	seen := map[string]bool{}
	for _, sig := range cdn.Registry {
		t.Run(sig.Name, func(t *testing.T) {
			assert.NotEmpty(t, sig.Name)
			assert.False(t, seen[sig.Name], "duplicate Signature.Name")
			seen[sig.Name] = true

			for _, ext := range sig.StaticExtensions {
				assert.Equal(t, strings.ToLower(ext), ext, "StaticExtensions entries must be lowercase")
				assert.False(t, strings.HasPrefix(ext, "."), "StaticExtensions entries must not include a leading dot")
			}

			for _, apex := range sig.ApexDomains {
				assert.Equal(t, strings.ToLower(apex), apex, "ApexDomains entries must be lowercase")
				assert.False(t, strings.HasPrefix(apex, "."), "ApexDomains entries must not include a leading dot")
			}

			for _, issue := range sig.KnownIssues {
				assert.NotEmpty(t, issue.ID)
				assert.NotEmpty(t, issue.Description)
				assert.True(t, strings.HasPrefix(issue.Reference, "http"), "KnownIssue.Reference should be a URL")
			}

			if sig.CacheKeyNormalizesBeforeCacheRules {
				assert.NotEmpty(t, sig.CacheKeyNotes, "CacheKeyNormalizesBeforeCacheRules=true should carry a CacheKeyNotes explanation")
			}
		})
	}
}
