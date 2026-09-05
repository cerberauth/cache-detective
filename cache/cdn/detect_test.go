package cdn_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/cache-detective/cache/cdn"
	"github.com/stretchr/testify/assert"
)

func TestDetect_Cloudflare(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "cloudflare")
	h.Set("CF-Cache-Status", "HIT")
	h.Set("Age", "42")

	d := cdn.Detect(h)
	assert.Equal(t, "Cloudflare", d.CDN)
	assert.Equal(t, cdn.StateHit, d.State)
	if assert.NotNil(t, d.Age) {
		assert.Equal(t, 42, *d.Age)
	}
}

func TestDetect_Fastly(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "Fastly")
	h.Set("X-Cache", "MISS")

	d := cdn.Detect(h)
	assert.Equal(t, "Fastly", d.CDN)
	assert.Equal(t, cdn.StateMiss, d.State)
}

func TestDetect_CloudFrontValueWithSuffix(t *testing.T) {
	h := http.Header{}
	h.Set("Via", "1.1 abc.cloudfront.net (CloudFront)")
	h.Set("X-Cache", "Hit from cloudfront")

	d := cdn.Detect(h)
	assert.Equal(t, "Amazon CloudFront", d.CDN)
	assert.Equal(t, cdn.StateHit, d.State)
}

func TestDetect_ServerTimingFallback(t *testing.T) {
	h := http.Header{}
	h.Set("Server-Timing", `cdn-cache; desc=HIT`)

	d := cdn.Detect(h)
	assert.Equal(t, cdn.StateHit, d.State)
	assert.Equal(t, "Server-Timing", d.Source)
}

func TestDetect_GenericXCacheFallback(t *testing.T) {
	h := http.Header{}
	h.Set("X-Cache", "cache-miss")

	d := cdn.Detect(h)
	assert.Equal(t, cdn.StateMiss, d.State)
}

func TestDetect_NoSignal(t *testing.T) {
	h := http.Header{}
	d := cdn.Detect(h)
	assert.Equal(t, cdn.StateUnknown, d.State)
	assert.Empty(t, d.CDN)
}

func TestMatchCNAME(t *testing.T) {
	sig, ok := cdn.MatchCNAME([]string{"www.example.com.", "d123.cloudfront.net."})
	assert.True(t, ok)
	assert.Equal(t, "Amazon CloudFront", sig.Name)
}
