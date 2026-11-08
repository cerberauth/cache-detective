// Package crawl implements §7 of cache-detective: resolving a scan's
// resource list ahead of time — from a single URL, a newline-delimited
// list file, a sitemap.xml, a .har import, or a same-origin crawl — into
// the []checkbase.ResourceSpec every check's DiscoveryCheck publishes.
//
// Crawling happens before the harnessx engine runs. Resolving the resource
// list up front, rather than as a harnessx Check, keeps the dependency
// graph simple (every check just depends on DiscoveryCheck) and lets a
// crawl's own courtesy/rate-limiting concerns (§10: robots.txt,
// same-origin/path-prefix scope) live in one place instead of being
// re-solved inside the check DAG.
package crawl

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// FromURLs turns a flat list of URLs into ResourceSpecs, IDing each by its
// path (or the full URL when paths collide).
func FromURLs(urls []string) []checkbase.ResourceSpec {
	specs := make([]checkbase.ResourceSpec, 0, len(urls))
	seen := map[string]int{}
	for _, u := range urls {
		id := resourceID(u)
		if n := seen[id]; n > 0 {
			id = fmt.Sprintf("%s#%d", id, n+1)
		}
		seen[id]++
		specs = append(specs, checkbase.ResourceSpec{ID: id, URL: u})
	}
	return specs
}

func resourceID(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return rawURL
	}
	return u.Path
}

// FromListFile reads a newline-delimited list of URLs from path, skipping
// blank lines and "#"-prefixed comments.
func FromListFile(path string) ([]checkbase.ResourceSpec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("crawl: reading list file: %w", err)
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("crawl: reading list file: %w", err)
	}
	return FromURLs(urls), nil
}

// sitemapDoc mirrors the subset of the sitemaps.org schema this package
// reads: either a <urlset> of <url><loc> or a <sitemapindex> of
// <sitemap><loc> entries pointing at further sitemaps.
type sitemapDoc struct {
	XMLName  xml.Name
	URLs     []sitemapLoc `xml:"url"`
	Sitemaps []sitemapLoc `xml:"sitemap"`
}

type sitemapLoc struct {
	Loc string `xml:"loc"`
}

const (
	// maxSitemapDepth bounds how many levels of <sitemapindex> nesting
	// FromSitemap follows.
	maxSitemapDepth = 3
	// maxSitemapBytes caps how much of one sitemap (after gzip
	// decompression) is read.
	maxSitemapBytes = 50 << 20
	// maxSitemapFetches caps the total number of sitemap documents fetched
	// for one FromSitemap call, guarding against huge or cyclic indexes.
	maxSitemapFetches = 50
)

// FromSitemap fetches and parses a sitemap.xml at sitemapURL. Sitemap
// indexes (<sitemapindex>) are followed up to maxSitemapDepth levels, and
// gzip-compressed sitemaps (.xml.gz) are transparently decompressed.
func FromSitemap(ctx context.Context, client *http.Client, sitemapURL string) ([]checkbase.ResourceSpec, error) {
	if client == nil {
		client = http.DefaultClient
	}
	var urls []string
	fetched := map[string]bool{}
	if err := collectSitemap(ctx, client, sitemapURL, 0, fetched, &urls); err != nil {
		return nil, err
	}
	return FromURLs(dedupe(urls)), nil
}

func collectSitemap(ctx context.Context, client *http.Client, sitemapURL string, depth int, fetched map[string]bool, urls *[]string) error {
	if fetched[sitemapURL] {
		return nil
	}
	if len(fetched) >= maxSitemapFetches {
		return fmt.Errorf("crawl: sitemap index references more than %d sitemaps", maxSitemapFetches)
	}
	fetched[sitemapURL] = true

	body, err := fetchSitemapBody(ctx, client, sitemapURL)
	if err != nil {
		return err
	}

	var doc sitemapDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("crawl: parsing sitemap: %w", err)
	}

	for _, u := range doc.URLs {
		if loc := strings.TrimSpace(u.Loc); loc != "" {
			*urls = append(*urls, loc)
		}
	}
	for _, sm := range doc.Sitemaps {
		loc := strings.TrimSpace(sm.Loc)
		if loc == "" {
			continue
		}
		if depth+1 > maxSitemapDepth {
			return fmt.Errorf("crawl: sitemap index nested deeper than %d levels", maxSitemapDepth)
		}
		if err := collectSitemap(ctx, client, loc, depth+1, fetched, urls); err != nil {
			return err
		}
	}
	return nil
}

func fetchSitemapBody(ctx context.Context, client *http.Client, sitemapURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sitemapURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req) //nolint:gosec // G704: fetching a caller-supplied sitemap URL is this package's purpose
	if err != nil {
		return nil, fmt.Errorf("crawl: fetching sitemap: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("crawl: fetching sitemap %s: unexpected status %d", sitemapURL, resp.StatusCode)
	}

	var r io.Reader = resp.Body
	br := bufio.NewReader(resp.Body)
	// Sniff the gzip magic number rather than trusting the URL suffix or
	// Content-Type: servers disagree on both for .xml.gz sitemaps.
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("crawl: decompressing sitemap: %w", err)
		}
		defer gz.Close()
		r = gz
	} else {
		r = br
	}

	body, err := io.ReadAll(io.LimitReader(r, maxSitemapBytes))
	if err != nil {
		return nil, fmt.Errorf("crawl: reading sitemap: %w", err)
	}
	return body, nil
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// FilterScope keeps only the specs whose URL is on the same host as origin
// and, when scope.PathPrefix is set, whose path is under that prefix. It
// applies the crawl scope rules (§7) to list, sitemap and .har inputs too.
func FilterScope(specs []checkbase.ResourceSpec, origin string, scope Scope) ([]checkbase.ResourceSpec, error) {
	base, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("crawl: parsing scope origin: %w", err)
	}
	out := make([]checkbase.ResourceSpec, 0, len(specs))
	for _, s := range specs {
		u, err := url.Parse(s.URL)
		if err != nil || u.Host != base.Host || !pathInScope(u.Path, scope.PathPrefix) {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}
