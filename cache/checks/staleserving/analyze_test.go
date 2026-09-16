package staleserving_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
	"github.com/cerberauth/cache-detective/cache/checks/staleserving"
)

func TestDeclaredFrom(t *testing.T) {
	cc := cacheability.ParseCacheControl("max-age=60, stale-while-revalidate=30, stale-if-error=120")
	d := staleserving.DeclaredFrom(cc)
	require := assert.New(t)
	require.NotNil(d.StaleWhileRevalidate)
	require.Equal(30, *d.StaleWhileRevalidate)
	require.NotNil(d.StaleIfError)
	require.Equal(120, *d.StaleIfError)
	require.True(d.Any())
}

func TestDeclared_Any_Empty(t *testing.T) {
	cc := cacheability.ParseCacheControl("max-age=60")
	d := staleserving.DeclaredFrom(cc)
	assert.False(t, d.Any())
}

func TestFreshnessLifetime_PrefersSMaxAge(t *testing.T) {
	cc := cacheability.ParseCacheControl("max-age=10, s-maxage=20")
	got := staleserving.FreshnessLifetime(cc, nil, time.Time{})
	assert.Equal(t, 20*time.Second, got)
}

func TestFreshnessLifetime_FallsBackToMaxAge(t *testing.T) {
	cc := cacheability.ParseCacheControl("max-age=10")
	got := staleserving.FreshnessLifetime(cc, nil, time.Time{})
	assert.Equal(t, 10*time.Second, got)
}

func TestFreshnessLifetime_FallsBackToExpires(t *testing.T) {
	cc := cacheability.ParseCacheControl("")
	date := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	expires := date.Add(5 * time.Minute)
	got := staleserving.FreshnessLifetime(cc, &expires, date)
	assert.Equal(t, 5*time.Minute, got)
}

func TestFreshnessLifetime_Unknown(t *testing.T) {
	cc := cacheability.ParseCacheControl("")
	got := staleserving.FreshnessLifetime(cc, nil, time.Time{})
	assert.Zero(t, got)
}

func TestAgeFromHeader(t *testing.T) {
	h := http.Header{}
	h.Set("Age", "42")
	assert.Equal(t, 42*time.Second, staleserving.AgeFromHeader(h))
	assert.Zero(t, staleserving.AgeFromHeader(http.Header{}))
}
