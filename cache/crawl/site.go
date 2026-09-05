package crawl

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Scope restricts a site-wide crawl (§7): same-origin always applies;
// PathPrefix additionally restricts discovery to URLs under that prefix.
type Scope struct {
	PathPrefix string
}

// Options configures Crawl.
type Options struct {
	Client        *http.Client
	Scope         Scope
	MaxPages      int
	RequestDelay  time.Duration
	RespectRobots bool
}

// hrefRe is a deliberately simple <a href="..."> extractor — good enough
// for discovering same-origin links without pulling in a full HTML parser
// dependency. It doesn't handle every malformed-HTML edge case a browser
// would.
var hrefRe = regexp.MustCompile(`(?i)<a\s+[^>]*href\s*=\s*["']([^"'#]+)["']`)

// Crawl performs a same-origin, breadth-first crawl starting at startURL,
// courteously spaced by opts.RequestDelay and capped at opts.MaxPages, and
// returns every discovered page as a ResourceSpec. When opts.RespectRobots
// is set, robots.txt disallow rules for "*" are honored (§10 courtesy).
func Crawl(ctx context.Context, startURL string, opts Options) ([]string, error) {
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	maxPages := opts.MaxPages
	if maxPages <= 0 {
		maxPages = 50
	}

	start, err := url.Parse(startURL)
	if err != nil {
		return nil, fmt.Errorf("crawl: parsing start URL: %w", err)
	}

	var disallow []string
	if opts.RespectRobots {
		disallow, _ = fetchRobotsDisallow(ctx, client, start)
	}

	visited := map[string]bool{}
	queue := []string{startURL}
	var found []string

	for len(queue) > 0 && len(found) < maxPages {
		next := queue[0]
		queue = queue[1:]
		if visited[next] {
			continue
		}
		visited[next] = true

		if opts.RequestDelay > 0 && len(found) > 0 {
			select {
			case <-ctx.Done():
				return found, ctx.Err()
			case <-time.After(opts.RequestDelay):
			}
		}

		body, links, err := fetchAndExtractLinks(ctx, client, next)
		if err != nil {
			continue
		}
		_ = body
		found = append(found, next)

		for _, link := range links {
			abs, ok := resolveInScope(start, link, opts.Scope)
			if !ok || visited[abs] || disallowed(abs, start, disallow) {
				continue
			}
			queue = append(queue, abs)
		}
	}

	return found, nil
}

func fetchAndExtractLinks(ctx context.Context, client *http.Client, pageURL string) (string, []string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := client.Do(req) //nolint:gosec // G704: crawling caller-supplied same-origin URLs is this package's purpose
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return "", nil, err
	}
	text := string(body)

	var links []string
	for _, m := range hrefRe.FindAllStringSubmatch(text, -1) {
		links = append(links, m[1])
	}
	return text, links, nil
}

func resolveInScope(start *url.URL, ref string, scope Scope) (string, bool) {
	u, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	abs := start.ResolveReference(u)
	if abs.Host != start.Host {
		return "", false
	}
	if scope.PathPrefix != "" && !strings.HasPrefix(abs.Path, scope.PathPrefix) {
		return "", false
	}
	abs.Fragment = ""
	return abs.String(), true
}

func fetchRobotsDisallow(ctx context.Context, client *http.Client, start *url.URL) ([]string, error) {
	robotsURL := (&url.URL{Scheme: start.Scheme, Host: start.Host, Path: "/robots.txt"}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req) //nolint:gosec // G704: same purpose as fetchAndExtractLinks above
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var disallow []string
	applies := false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(strings.ToLower(line), "user-agent:"):
			ua := strings.TrimSpace(line[len("user-agent:"):])
			applies = ua == "*"
		case applies && strings.HasPrefix(strings.ToLower(line), "disallow:"):
			path := strings.TrimSpace(line[len("disallow:"):])
			if path != "" {
				disallow = append(disallow, path)
			}
		}
	}
	return disallow, nil
}

func disallowed(pageURL string, start *url.URL, disallow []string) bool {
	u, err := url.Parse(pageURL)
	if err != nil {
		return false
	}
	for _, d := range disallow {
		if strings.HasPrefix(u.Path, d) {
			return true
		}
	}
	return false
}
