package geo_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/geo"
)

func TestNoopProvider(t *testing.T) {
	var p geo.Provider = geo.NoopProvider{}
	regions, err := p.Regions(context.Background())
	require.NoError(t, err)
	assert.Empty(t, regions)

	probes, err := p.ProbeFrom(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Empty(t, probes)
}

func cacheStatusHeader(v string) http.Header {
	h := http.Header{}
	h.Set("CF-Cache-Status", v)
	return h
}

func TestCompareCacheState_Inconsistent(t *testing.T) {
	probes := []geo.Probe{
		{Region: "us-east", Header: cacheStatusHeader("HIT")},
		{Region: "eu-west", Header: cacheStatusHeader("MISS")},
	}
	inc := geo.CompareCacheState("root", probes, "CF-Cache-Status")
	require.NotNil(t, inc)
	assert.Equal(t, "root", inc.ResourceID)
}

func TestCompareCacheState_Consistent(t *testing.T) {
	probes := []geo.Probe{
		{Region: "us-east", Header: cacheStatusHeader("HIT")},
		{Region: "eu-west", Header: cacheStatusHeader("HIT")},
	}
	inc := geo.CompareCacheState("root", probes, "CF-Cache-Status")
	assert.Nil(t, inc)
}
