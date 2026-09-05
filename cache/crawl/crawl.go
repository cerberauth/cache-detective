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

// sitemapURLSet mirrors the subset of the sitemaps.org schema this package
// reads: a flat <urlset> of <url><loc>.
type sitemapURLSet struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
}

// FromSitemap fetches and parses a sitemap.xml at sitemapURL. Sitemap
// indexes (<sitemapindex>) are not followed recursively in v1 — only a
// flat <urlset> is supported.
func FromSitemap(ctx context.Context, client *http.Client, sitemapURL string) ([]checkbase.ResourceSpec, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sitemapURL, nil)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req) //nolint:gosec // G704: fetching a caller-supplied sitemap URL is this package's purpose
	if err != nil {
		return nil, fmt.Errorf("crawl: fetching sitemap: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("crawl: reading sitemap: %w", err)
	}

	var set sitemapURLSet
	if err := xml.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("crawl: parsing sitemap: %w", err)
	}

	urls := make([]string, 0, len(set.URLs))
	for _, u := range set.URLs {
		if u.Loc != "" {
			urls = append(urls, u.Loc)
		}
	}
	return FromURLs(urls), nil
}
