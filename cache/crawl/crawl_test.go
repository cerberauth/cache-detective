package crawl_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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

	specs, err := crawl.FromHAR(path)
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
