package cacheability

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func header(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Set(pairs[i], pairs[i+1])
	}
	return h
}

func TestAnalyze_NoStore(t *testing.T) {
	res := Analyze("GET", 200, header("Cache-Control", "no-store"), false)
	assert.False(t, res.Cacheable)
	assert.Contains(t, res.Reasons[0], "no-store")
}

func TestAnalyze_PublicMaxAge(t *testing.T) {
	res := Analyze("GET", 200, header("Cache-Control", "public, max-age=3600", "ETag", `"abc"`), false)
	assert.True(t, res.Cacheable)
	assert.Empty(t, res.Findings)
}

func TestAnalyze_MissingValidators(t *testing.T) {
	res := Analyze("GET", 200, header("Cache-Control", "public, max-age=3600"), false)
	assert.True(t, res.Cacheable)
	assert.Len(t, res.Findings, 1)
	assert.Equal(t, "Cacheable response missing validators", res.Findings[0].Title)
}

func TestAnalyze_ConflictingNoStoreMaxAge(t *testing.T) {
	res := Analyze("GET", 200, header("Cache-Control", "no-store, max-age=3600"), false)
	assert.False(t, res.Cacheable)
	if assert.NotEmpty(t, res.Findings) {
		assert.Equal(t, "Conflicting Cache-Control directives", res.Findings[0].Title)
	}
}

func TestAnalyze_PublicPrivateConflict(t *testing.T) {
	res := Analyze("GET", 200, header("Cache-Control", "public, private, max-age=60", "ETag", `"x"`), false)
	assert.NotEmpty(t, res.Findings)
	assert.Equal(t, "Conflicting Cache-Control directives", res.Findings[0].Title)
}

func TestAnalyze_PostNotCacheableWithoutFreshness(t *testing.T) {
	res := Analyze("POST", 200, header(), false)
	assert.False(t, res.Cacheable)
}

func TestAnalyze_PostCacheableWithExplicitFreshness(t *testing.T) {
	res := Analyze("POST", 200, header("Cache-Control", "max-age=60", "ETag", `"x"`), false)
	assert.True(t, res.Cacheable)
}

func TestAnalyze_PutNeverCacheable(t *testing.T) {
	res := Analyze("PUT", 200, header("Cache-Control", "public, max-age=60"), false)
	assert.False(t, res.Cacheable)
}

func TestAnalyze_StatusDefaultCacheableWithoutDirectives(t *testing.T) {
	res := Analyze("GET", 404, header(), false)
	assert.True(t, res.Cacheable)
}

func TestAnalyze_StatusNotDefaultCacheable(t *testing.T) {
	res := Analyze("GET", 500, header(), false)
	assert.False(t, res.Cacheable)
}

func TestAnalyze_PragmaFallback(t *testing.T) {
	res := Analyze("GET", 200, header("Pragma", "no-cache"), false)
	if assert.NotEmpty(t, res.Findings) {
		assert.Equal(t, "Legacy Pragma fallback in use", res.Findings[0].Title)
	}
}

func TestAnalyze_VaryParsed(t *testing.T) {
	res := Analyze("GET", 200, header("Vary", "Accept-Encoding, Accept-Language"), false)
	assert.Equal(t, []string{"Accept-Encoding", "Accept-Language"}, res.Vary)
}

func TestAnalyze_ExpiresParsed(t *testing.T) {
	res := Analyze("GET", 200, header("Expires", "Wed, 21 Oct 2099 07:28:00 GMT"), false)
	if assert.NotNil(t, res.Expires) {
		assert.Equal(t, 2099, res.Expires.Year())
	}
}

func TestParseCacheControl(t *testing.T) {
	cc := ParseCacheControl(`public, max-age=100, s-maxage=200, stale-while-revalidate=30, must-revalidate`)
	assert.True(t, cc.Public)
	assert.True(t, cc.MustRevalidate)
	if assert.NotNil(t, cc.MaxAge) {
		assert.Equal(t, 100, *cc.MaxAge)
	}
	if assert.NotNil(t, cc.SMaxAge) {
		assert.Equal(t, 200, *cc.SMaxAge)
	}
	if assert.NotNil(t, cc.StaleWhileRevalidate) {
		assert.Equal(t, 30, *cc.StaleWhileRevalidate)
	}
}
