package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetScanInputs(t *testing.T) {
	t.Helper()
	scanURL, scanListFile, scanSitemapURL, scanHARFile = "", "", "", ""
	scanHARReplay, scanCrawl, scanMaxPages, scanCrawlDelay, scanRateLimit = false, false, 0, 0, 0
	t.Cleanup(func() {
		scanURL, scanListFile, scanSitemapURL, scanHARFile = "", "", "", ""
		scanHARReplay, scanCrawl, scanMaxPages, scanCrawlDelay, scanRateLimit = false, false, 0, 0, 0
	})
}

func TestResolveResources_SingleURL(t *testing.T) {
	resetScanInputs(t)
	scanURL = "https://example.com/"
	specs, target, err := resolveResources(context.Background())
	require.NoError(t, err)
	require.Len(t, specs, 1)
	assert.Equal(t, "https://example.com/", target)
}

func TestResolveResources_Validation(t *testing.T) {
	resetScanInputs(t)
	_, _, err := resolveResources(context.Background())
	require.Error(t, err, "no source")

	scanURL, scanListFile = "https://example.com/", "urls.txt"
	_, _, err = resolveResources(context.Background())
	require.Error(t, err, "two sources")

	scanURL, scanListFile, scanCrawl = "", "", true
	_, _, err = resolveResources(context.Background())
	require.Error(t, err, "--crawl without --url")

	scanURL, scanHARReplay = "https://example.com/", true
	_, _, err = resolveResources(context.Background())
	require.Error(t, err, "--har-replay-headers without --har")

	scanURL, scanHARReplay, scanCrawl, scanRateLimit = "https://example.com/", false, false, -1
	_, _, err = resolveResources(context.Background())
	require.Error(t, err, "negative rate limit")
}

func TestProbeOptions_RateLimit(t *testing.T) {
	resetScanInputs(t)
	base := len(probeOptions())
	scanRateLimit = 2.5
	assert.Len(t, probeOptions(), base+1)
}
