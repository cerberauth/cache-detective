package crawl_test

import (
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/crawl"
)

func TestFromURLs(t *testing.T) {
	specs := crawl.FromURLs([]string{"https://example.com/a", "https://example.com/b"})
	require.Len(t, specs, 2)
	assert.Equal(t, "/a", specs[0].ID)
	assert.Equal(t, "/b", specs[1].ID)
}

func TestFromListFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "urls.txt")
	require.NoError(t, os.WriteFile(path, []byte("# comment\nhttps://example.com/a\n\nhttps://example.com/b\n"), 0o644))

	specs, err := crawl.FromListFile(path)
	require.NoError(t, err)
	require.Len(t, specs, 2)
}

func TestFromSitemap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/a</loc></url>
  <url><loc>https://example.com/b</loc></url>
</urlset>`))
	}))
	defer srv.Close()

	specs, err := crawl.FromSitemap(context.Background(), srv.Client(), srv.URL)
	require.NoError(t, err)
	require.Len(t, specs, 2)
}

func TestFromHAR(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.har")
	har := `{"log":{"entries":[
		{"request":{"method":"GET","url":"https://example.com/a"}},
		{"request":{"method":"POST","url":"https://example.com/submit"}},
		{"request":{"method":"GET","url":"https://example.com/a"}}
	]}}`
	require.NoError(t, os.WriteFile(path, []byte(har), 0o644))

	specs, err := crawl.FromHAR(path, crawl.HAROptions{})
	require.NoError(t, err)
	require.Len(t, specs, 1)
	assert.Equal(t, "https://example.com/a", specs[0].URL)
}

func TestCrawl_SameOriginOnly(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<a href="/page2">p2</a><a href="https://external.example.com/x">ext</a>`))
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`no links here`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	found, err := crawl.Crawl(context.Background(), srv.URL+"/", crawl.Options{Client: srv.Client()})
	require.NoError(t, err)
	assert.Len(t, found, 2)
}

func TestCrawl_PathPrefixScope(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/blog/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<a href="/blog/post1">p1</a><a href="/other">other</a>`))
	})
	mux.HandleFunc("/blog/post1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(``))
	})
	mux.HandleFunc("/other", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(``))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	found, err := crawl.Crawl(context.Background(), srv.URL+"/blog/", crawl.Options{
		Client: srv.Client(),
		Scope:  crawl.Scope{PathPrefix: "/blog"},
	})
	require.NoError(t, err)
	assert.Len(t, found, 2) // /blog/ and /blog/post1, not /other
}

func TestCrawl_RespectsRobots(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /private\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<a href="/private/secret">p</a><a href="/public">pub</a>`))
	})
	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(``))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	found, err := crawl.Crawl(context.Background(), srv.URL+"/", crawl.Options{
		Client:        srv.Client(),
		RespectRobots: true,
	})
	require.NoError(t, err)
	assert.Len(t, found, 2) // "/" and "/public", not "/private/secret"
	for _, f := range found {
		assert.NotContains(t, f, "/private")
	}
}

func TestFromSitemap_IndexAndGzip(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/index.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>http://` + r.Host + `/a.xml</loc></sitemap>
  <sitemap><loc>http://` + r.Host + `/b.xml.gz</loc></sitemap>
</sitemapindex>`))
	})
	mux.HandleFunc("/a.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<urlset><url><loc>https://example.com/a</loc></url><url><loc>https://example.com/shared</loc></url></urlset>`))
	})
	mux.HandleFunc("/b.xml.gz", func(w http.ResponseWriter, r *http.Request) {
		gz := gzip.NewWriter(w)
		gz.Write([]byte(`<urlset><url><loc>https://example.com/b</loc></url><url><loc>https://example.com/shared</loc></url></urlset>`))
		gz.Close()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	specs, err := crawl.FromSitemap(context.Background(), srv.Client(), srv.URL+"/index.xml")
	require.NoError(t, err)
	require.Len(t, specs, 3) // a, shared, b — "shared" deduplicated
}

func TestFromSitemap_IndexCycle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<sitemapindex><sitemap><loc>http://` + r.Host + `/self.xml</loc></sitemap></sitemapindex>`))
	}))
	defer srv.Close()

	specs, err := crawl.FromSitemap(context.Background(), srv.Client(), srv.URL+"/self.xml")
	require.NoError(t, err)
	assert.Empty(t, specs)
}

func TestFromSitemap_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	_, err := crawl.FromSitemap(context.Background(), srv.Client(), srv.URL)
	require.Error(t, err)
}

func TestFilterScope(t *testing.T) {
	specs := crawl.FromURLs([]string{
		"https://example.com/blog",
		"https://example.com/blog/post",
		"https://example.com/blogger",
		"https://example.com/other",
		"https://cdn.example.com/blog/x",
	})
	got, err := crawl.FilterScope(specs, "https://example.com/sitemap.xml", crawl.Scope{PathPrefix: "/blog"})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "https://example.com/blog", got[0].URL)
	assert.Equal(t, "https://example.com/blog/post", got[1].URL)
}

func TestFromHAR_KeepsMethod(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.har")
	har := `{"log":{"entries":[
		{"request":{"method":"GET","url":"https://example.com/a"}},
		{"request":{"method":"head","url":"https://example.com/a"}},
		{"request":{"method":"GET","url":"https://example.com/b?x=1"}}
	]}}`
	require.NoError(t, os.WriteFile(path, []byte(har), 0o644))

	specs, err := crawl.FromHAR(path, crawl.HAROptions{})
	require.NoError(t, err)
	require.Len(t, specs, 3)
	assert.Equal(t, "HEAD", specs[1].Method)
	assert.NotEqual(t, specs[0].ID, specs[1].ID)
}

func TestCrawl_RequestDelayAndMaxPages(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<a href="/1">1</a><a href="/2">2</a><a href="/3">3</a>`))
	})
	mux.HandleFunc("/1", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/2", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/3", func(w http.ResponseWriter, r *http.Request) {})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	start := time.Now()
	found, err := crawl.Crawl(context.Background(), srv.URL+"/", crawl.Options{
		Client:       srv.Client(),
		MaxPages:     3,
		RequestDelay: 30 * time.Millisecond,
	})
	require.NoError(t, err)
	assert.Len(t, found, 3)
	assert.GreaterOrEqual(t, time.Since(start), 60*time.Millisecond)
}

func TestFromHAR_ReplayRequestHeaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.har")
	har := `{"log":{"entries":[{"request":{"method":"GET","url":"https://example.com/account",
		"headers":[
			{"name":":authority","value":"example.com"},
			{"name":"Host","value":"example.com"},
			{"name":"accept-language","value":"fr-FR"},
			{"name":"Authorization","value":"Bearer tok"},
			{"name":"If-None-Match","value":"\"abc\""},
			{"name":"Cache-Control","value":"no-cache"},
			{"name":"Cookie","value":"sid=1; theme=dark"}
		],
		"cookies":[{"name":"ignored","value":"x"}]}}]}}`
	require.NoError(t, os.WriteFile(path, []byte(har), 0o644))

	off, err := crawl.FromHAR(path, crawl.HAROptions{})
	require.NoError(t, err)
	assert.Empty(t, off[0].Headers)
	assert.Empty(t, off[0].Cookies)

	on, err := crawl.FromHAR(path, crawl.HAROptions{ReplayRequestHeaders: true})
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{
		"Accept-Language": {"fr-FR"},
		"Authorization":   {"Bearer tok"},
	}, on[0].Headers)
	require.Len(t, on[0].Cookies, 2)
	assert.Equal(t, "sid", on[0].Cookies[0].Name)
	assert.Equal(t, "theme", on[0].Cookies[1].Name)
}
