package cdn_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wantCDNs is the minimum set of vendors the registry must carry a
// Signature for (Issue #33's seed list) — a regression net against an
// entry being accidentally dropped, not an exhaustive list.
var wantCDNs = []string{
	"Cloudflare", "Fastly", "Amazon CloudFront", "Varnish", "Vercel",
	"Netlify", "Akamai", "Google Cloud CDN", "Azure Front Door", "Nginx",
	"KeyCDN", "Bunny CDN",
}

func TestRegistry_HasSeedCDNs(t *testing.T) {
	names := make(map[string]bool, len(cdn.Registry))
	for _, sig := range cdn.Registry {
		names[sig.Name] = true
	}
	for _, want := range wantCDNs {
		assert.True(t, names[want], "Registry is missing a Signature for %q", want)
	}
}

func TestRegistry_EntriesAreWellFormed(t *testing.T) {
	for _, sig := range cdn.Registry {
		t.Run(sig.Name, func(t *testing.T) {
			require.NotEmpty(t, sig.Name)

			// A Signature needs at least one way to be identified: its own
			// cache-status header, a Server/Via fingerprint, or a CNAME apex.
			hasIdentity := sig.CacheStatusHeader != "" || len(sig.ServerMatch) > 0 || len(sig.ViaMatch) > 0 || len(sig.ApexDomains) > 0
			assert.True(t, hasIdentity, "%s has no CacheStatusHeader, ServerMatch, ViaMatch, or ApexDomains to identify it by", sig.Name)

			for ext := range sig.StatusValues {
				assert.Equal(t, strings.ToLower(ext), ext, "%s StatusValues key %q should be lowercase (Normalize matches case-insensitively via lowercasing)", sig.Name, ext)
			}

			for _, ext := range sig.StaticExtensions {
				assert.True(t, strings.HasPrefix(ext, "."), "%s StaticExtensions entry %q should start with '.'", sig.Name, ext)
			}

			for _, q := range sig.Quirks {
				assert.NotEmpty(t, q.ID, "%s has a Quirk with no ID", sig.Name)
				assert.NotEmpty(t, q.Description, "%s Quirk %q has no Description", sig.Name, q.ID)
				assert.True(t, strings.HasPrefix(q.Reference, "https://") || strings.HasPrefix(q.Reference, "http://"), "%s Quirk %q Reference %q should be a URL", sig.Name, q.ID, q.Reference)
			}
		})
	}
}

func TestAllStaticExtensions_DedupedAndNormalized(t *testing.T) {
	exts := cdn.AllStaticExtensions()
	require.NotEmpty(t, exts)

	seen := make(map[string]bool, len(exts))
	for _, ext := range exts {
		assert.True(t, strings.HasPrefix(ext, "."), "extension %q should start with '.'", ext)
		assert.False(t, seen[ext], "extension %q appears more than once", ext)
		seen[ext] = true
	}
	assert.Contains(t, exts, ".css")
	assert.Contains(t, exts, ".js")
}

func TestDetect_GoogleCloudCDN(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "Google Frontend")
	h.Set("Age", "10")

	sig, ok := cdn.MatchServer(h.Get("Server"), h.Get("Via"))
	require.True(t, ok)
	assert.Equal(t, "Google Cloud CDN", sig.Name)
}

func TestDetect_AzureFrontDoor(t *testing.T) {
	h := http.Header{}
	h.Set("X-Cache", "TCP_HIT")

	sig, ok := cdn.MatchCNAME([]string{"contoso.azurefd.net."})
	require.True(t, ok)
	assert.Equal(t, "Azure Front Door", sig.Name)

	state, ok := sig.Normalize(h.Get("X-Cache"))
	require.True(t, ok)
	assert.Equal(t, cdn.StateHit, state)
}

func TestDetect_Nginx(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.25.3")
	h.Set("X-Cache-Status", "HIT")

	sig, ok := cdn.MatchServer(h.Get("Server"), h.Get("Via"))
	require.True(t, ok)
	assert.Equal(t, "Nginx", sig.Name)

	state, ok := sig.Normalize(h.Get("X-Cache-Status"))
	require.True(t, ok)
	assert.Equal(t, cdn.StateHit, state)
}

func TestDetect_BunnyCDN(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "BunnyCDN")
	h.Set("CDN-Cache", "MISS")

	sig, ok := cdn.MatchServer(h.Get("Server"), h.Get("Via"))
	require.True(t, ok)
	assert.Equal(t, "Bunny CDN", sig.Name)

	state, ok := sig.Normalize(h.Get("CDN-Cache"))
	require.True(t, ok)
	assert.Equal(t, cdn.StateMiss, state)
}

func TestDetect_KeyCDN(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "keycdn-engine")
	h.Set("X-Cache", "HIT")

	sig, ok := cdn.MatchServer(h.Get("Server"), h.Get("Via"))
	require.True(t, ok)
	assert.Equal(t, "KeyCDN", sig.Name)
}
