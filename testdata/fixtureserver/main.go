// Command fixtureserver is a small HTTP server used by the "Scans" CI
// workflow to exercise cache-detective against known-vulnerable and
// known-fixed cache behavior. There's no published fixture image for this
// yet, so it ships here as a `go run`-able program instead — not part of
// the module's tested package tree (testdata/ is excluded from
// `go build ./...`/`go vet ./...` by the Go toolchain).
//
// Usage: go run ./testdata/fixtureserver -addr :8080 -vulnerable=true
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	vulnerable := flag.Bool("vulnerable", false, "serve the vulnerable variant of each fixture")
	flag.Parse()

	mux := http.NewServeMux()

	// /cacheable: always properly cacheable, with a validator — the
	// "everything is fine" baseline.
	mux.HandleFunc("/cacheable", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte("cacheable content"))
	})

	// /no-store: never cacheable.
	mux.HandleFunc("/no-store", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("private content"))
	})

	// /account (and, in vulnerable mode, any path confusable with it —
	// /account.js, /account/nonexistent.css, ...): serves the same
	// "authenticated" payload regardless of path suffix and marks it
	// cacheable — a cache deception surface. Registered with a trailing
	// slash plus an exact match since http.ServeMux's prefix matching alone
	// doesn't cover "/account.js" (no path separator after the prefix). In
	// fixed mode, only the exact path is served, and privately.
	accountHandler := func(w http.ResponseWriter, r *http.Request) {
		if *vulnerable {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		} else {
			w.Header().Set("Cache-Control", "private, no-store")
		}
		_, _ = w.Write([]byte("secret-account-data"))
	}
	mux.HandleFunc("/account", accountHandler)
	mux.HandleFunc("/account.js", func(w http.ResponseWriter, r *http.Request) {
		if *vulnerable {
			accountHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/account.css", func(w http.ResponseWriter, r *http.Request) {
		if *vulnerable {
			accountHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/account/", func(w http.ResponseWriter, r *http.Request) {
		if *vulnerable {
			accountHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})

	// /poison: in vulnerable mode, simulates an unkeyed X-Forwarded-Host
	// cache: a plain request (the header absent) is served whatever was
	// last poisoned (or the default, if never poisoned); a request that
	// sets the header immediately re-poisons the shared entry with the
	// reflected value, which every subsequent plain request then sees. In
	// fixed mode the header has no effect.
	cachedPoison := "host=origin.example.com"
	mux.HandleFunc("/poison", func(w http.ResponseWriter, r *http.Request) {
		if !*vulnerable {
			_, _ = w.Write([]byte("host=origin.example.com"))
			return
		}
		if v := r.Header.Get("X-Forwarded-Host"); v != "" {
			cachedPoison = "host=" + v
		}
		_, _ = w.Write([]byte(cachedPoison))
	})

	// /poison-cookie and /poison-param: the same unkeyed, single-slot cache
	// simulation as /poison, but driven by a "debug" cookie / "debug" query
	// parameter instead of a header — both are bundled default-wordlist
	// candidates the unkeyed-input miner (§5) mines by default, exercising
	// its cookie and query-parameter axes alongside the existing
	// header-axis /poison fixture.
	cachedCookiePoison := "debug="
	mux.HandleFunc("/poison-cookie", func(w http.ResponseWriter, r *http.Request) {
		if !*vulnerable {
			_, _ = w.Write([]byte("debug="))
			return
		}
		if c, err := r.Cookie("debug"); err == nil && c.Value != "" {
			cachedCookiePoison = "debug=" + c.Value
		}
		_, _ = w.Write([]byte(cachedCookiePoison))
	})

	cachedParamPoison := "debug="
	mux.HandleFunc("/poison-param", func(w http.ResponseWriter, r *http.Request) {
		if !*vulnerable {
			_, _ = w.Write([]byte("debug="))
			return
		}
		if v := r.URL.Query().Get("debug"); v != "" {
			cachedParamPoison = "debug=" + v
		}
		_, _ = w.Write([]byte(cachedParamPoison))
	})

	// /stale: exercises the stale-while-revalidate / stale-if-error check
	// (§9). In fixed mode it behaves like a real edge cache: it serves the
	// last-known-good body promptly once the response enters its
	// stale-while-revalidate window (instead of blocking on a synchronous
	// origin refetch), and keeps serving that body — instead of a 5xx —
	// when the caller signals a simulated origin failure via
	// X-Cache-Detective-Simulate-Error, as long as the request is still
	// within stale-if-error's window. In vulnerable mode neither directive
	// is actually honored: every request past max-age blocks on a
	// synchronous refetch, and a simulated origin failure always surfaces
	// as a 500 regardless of stale-if-error.
	edge := &staleEdgeCache{
		maxAge: time.Second,
		swr:    3 * time.Second,
		sie:    5 * time.Second,
		honor:  !*vulnerable,
	}
	mux.HandleFunc("/stale", edge.handler)

	registerCacheKeyFixtures(mux, *vulnerable)
	registerResponseFixtures(mux, *vulnerable)

	// http.ServeMux 301-redirects any path containing "." / ".." segments to
	// its cleaned form, which would hide the very traversal the path
	// fixtures below exist to serve. So requests under /static/ and /assets/
	// (and the random single-segment paths the key-collision probe visits)
	// are routed on their raw path here, ahead of the mux.
	raw := newRawPathFixtures(*vulnerable)
	// /me: the authenticated resource the /static/ traversal fixtures resolve
	// to (cache-deception-static-directory); by its own path it is private.
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) { raw.serveMe(w, r, false) })
	pathMapping := newPathMappingFixtures(*vulnerable)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := pathMapping.handles(r); ok {
			h(w, r)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/static/"):
			raw.staticDir(w, r)
		case strings.HasPrefix(r.URL.Path, "/assets/"), collisionVictimPath.MatchString(r.URL.Path):
			raw.collision(w, r)
		default:
			mux.ServeHTTP(w, r)
		}
	})

	log.Printf("fixtureserver listening on %s (vulnerable=%v)", *addr, *vulnerable)
	log.Fatal(http.ListenAndServe(*addr, handler)) //nolint:gosec // G114: fixed-duration CI fixture, not a production server
}

// staleEdgeCache is a minimal in-memory stand-in for a fronting CDN's
// freshness/stale-serving logic, used by /stale to give the stale-serving
// check (§9) something real to observe over the wire.
type staleEdgeCache struct {
	mu        sync.Mutex
	fetchedAt time.Time
	body      string
	honor     bool
	maxAge    time.Duration
	swr       time.Duration
	sie       time.Duration
}

func (c *staleEdgeCache) handler(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if c.fetchedAt.IsZero() {
		c.fetchedAt = now
		c.body = "stale-serving fixture content"
	}
	age := now.Sub(c.fetchedAt)

	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, stale-while-revalidate=%d, stale-if-error=%d", int(c.maxAge.Seconds()), int(c.swr.Seconds()), int(c.sie.Seconds())))

	if r.Header.Get("X-Cache-Detective-Simulate-Error") != "" {
		if c.honor && age < c.maxAge+c.swr+c.sie {
			w.Header().Set("Age", fmt.Sprintf("%d", int(age.Seconds())))
			_, _ = w.Write([]byte(c.body))
			return
		}
		http.Error(w, "simulated origin failure", http.StatusInternalServerError)
		return
	}

	switch {
	case age < c.maxAge:
		w.Header().Set("Age", fmt.Sprintf("%d", int(age.Seconds())))
		_, _ = w.Write([]byte(c.body))
	case age < c.maxAge+c.swr && c.honor:
		w.Header().Set("Age", fmt.Sprintf("%d", int(age.Seconds())))
		_, _ = w.Write([]byte(c.body))
		c.fetchedAt = now // background revalidation, completed instantly
	case age < c.maxAge+c.swr && !c.honor:
		time.Sleep(300 * time.Millisecond) // blocks on a synchronous refetch
		c.fetchedAt = now
		w.Header().Set("Age", "0")
		_, _ = w.Write([]byte(c.body))
	default:
		c.fetchedAt = now
		w.Header().Set("Age", "0")
		_, _ = w.Write([]byte(c.body))
	}
}

// simResponse is one entry in a fixture's simulated shared cache.
type simResponse struct {
	status int
	body   string
}

// simCache is a minimal in-memory shared cache that reports its verdict in
// X-Cache (MISS, then HIT for the same key) — the generic header
// cache-detective's live-state fallback reads — and never expires, like the
// api-vulns-challenges caches these fixtures mirror.
type simCache struct {
	mu    sync.Mutex
	store map[string]simResponse
}

func newSimCache() *simCache { return &simCache{store: map[string]simResponse{}} }

func (c *simCache) get(key string) (simResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.store[key]
	return e, ok
}

func (c *simCache) put(key string, e simResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = e
}

// write sends e with the given X-Cache state.
func (e simResponse) write(w http.ResponseWriter, state string) {
	w.Header().Set("X-Cache", state)
	w.WriteHeader(e.status)
	_, _ = w.Write([]byte(e.body))
}

// serveCached answers from c on a hit, else fills it from produce.
func (c *simCache) serveCached(w http.ResponseWriter, key string, produce func() simResponse) {
	if e, ok := c.get(key); ok {
		e.write(w, "HIT")
		return
	}
	e := produce()
	c.put(key, e)
	e.write(w, "MISS")
}

// registerCacheKeyFixtures registers the fixtures for inputs the cache key
// ignores or over-counts. Each mirrors an api-vulns-challenges challenge:
//
//	/fat-get   cache-poisoning-fat-get          GET body overrides ?q
//	/cloak     cache-poisoning-parameter-cloaking  ";name=" hidden from the key
//	/explode   cache-key-explosion-dos          unbounded entries per ?q value
//	/vault     proxy-cache-deception            key ignores Authorization
func registerCacheKeyFixtures(mux *http.ServeMux, vulnerable bool) {
	// /fat-get?q=term: a URL-keyed cache in front of an origin that, when
	// vulnerable, lets a GET request body override q.
	fat := newSimCache()
	mux.HandleFunc("/fat-get", func(w http.ResponseWriter, r *http.Request) {
		fat.serveCached(w, r.URL.RequestURI(), func() simResponse {
			term := r.URL.Query().Get("q")
			if vulnerable {
				if b, err := io.ReadAll(r.Body); err == nil && len(b) > 0 {
					term = string(b)
				}
			}
			return simResponse{http.StatusOK, "Results for: " + term}
		})
	})

	// /cloak?id=1: when vulnerable, the cache keys on the query only up to the
	// first ";" while the origin reads "name" from after one (Rails-style).
	cloak := newSimCache()
	mux.HandleFunc("/cloak", func(w http.ResponseWriter, r *http.Request) {
		rawQuery := r.URL.RawQuery
		key := r.URL.Path + "?" + rawQuery
		if vulnerable {
			key = r.URL.Path + "?" + strings.SplitN(rawQuery, ";", 2)[0]
		}
		cloak.serveCached(w, key, func() simResponse {
			name := "world"
			if vulnerable {
				for _, part := range strings.Split(rawQuery, ";") {
					if v, ok := strings.CutPrefix(part, "name="); ok {
						name = v
					}
				}
			} else if v := r.URL.Query().Get("name"); v != "" {
				name = v
			}
			return simResponse{http.StatusOK, "Hello, " + name + "!"}
		})
	})

	// /explode?q=value: when vulnerable, every distinct q is its own cache
	// entry without limit. Fixed, entries beyond maxExplodeKeys share one
	// overflow bucket.
	const maxExplodeKeys = 16
	var explodeMu sync.Mutex
	explodeStore := map[string]bool{}
	mux.HandleFunc("/explode", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("q")
		explodeMu.Lock()
		if !vulnerable && !explodeStore[key] && len(explodeStore) >= maxExplodeKeys {
			key = "__overflow__"
		}
		hit := explodeStore[key]
		explodeStore[key] = true
		explodeMu.Unlock()

		if hit {
			w.Header().Set("X-Cache", "HIT")
		} else {
			w.Header().Set("X-Cache", "MISS")
		}
		_, _ = w.Write([]byte(`{"results": []}`))
	})

	// /vault: private data behind a cache that, when vulnerable, keys on the
	// path alone — ignoring both Authorization and the query string — so the
	// first caller's response is replayed to everyone. Fixed, the key includes
	// the Authorization value.
	vault := newSimCache()
	mux.HandleFunc("/vault", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		key := r.URL.Path
		if !vulnerable {
			key += "|" + auth
		}
		vault.serveCached(w, key, func() simResponse {
			if auth == "" {
				// Not stored: only 2xx responses are worth caching here.
				return simResponse{http.StatusUnauthorized, "unauthorized"}
			}
			return simResponse{http.StatusOK, fmt.Sprintf(`{"vault": "private data for %s"}`, auth)}
		})
	})
}

// registerResponseFixtures registers fixtures judged from the response
// alone, with no cache simulation:
//
//	/session    cache-sensitive-data-exposure   cacheable Set-Cookie + CSRF token
//	/validator  cache-conditional-validators    flapping ETag, conditionals ignored
//	/flaky      cache-freshness-heuristic       error status cached with no freshness
func registerResponseFixtures(mux *http.ServeMux, vulnerable bool) {
	// /session mints a session cookie and a CSRF token per request. Fixed, the
	// response says it is private; vulnerable, nothing does.
	mux.HandleFunc("/session", func(w http.ResponseWriter, r *http.Request) {
		token := fmt.Sprintf("%x", time.Now().UnixNano())
		http.SetCookie(w, &http.Cookie{Name: "session", Value: token, HttpOnly: true, Path: "/"})
		if !vulnerable {
			w.Header().Set("Cache-Control", "private, no-store")
		}
		_, _ = fmt.Fprintf(w, `{"user": "fixture", "csrf_token": %q}`, token)
	})

	// /validator is a static document. Vulnerable, it issues a new ETag on
	// every response and ignores conditional requests; fixed, the ETag is
	// stable and If-None-Match is honored with 304.
	mux.HandleFunc("/validator", func(w http.ResponseWriter, r *http.Request) {
		if vulnerable {
			w.Header().Set("ETag", fmt.Sprintf(`"%x"`, time.Now().UnixNano()))
			_, _ = w.Write([]byte("validator fixture content"))
			return
		}
		w.Header().Set("ETag", `"validator-v1"`)
		if r.Header.Get("If-None-Match") == `"validator-v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte("validator fixture content"))
	})

	// /flaky always fails with a 500 and declares no freshness. RFC 9110 §15.1
	// doesn't list 500 among the statuses a cache may store by default; the
	// vulnerable cache stores it anyway. (500, not the challenge's 503: the
	// probe library retries 503s and discards them, so one can't be scanned.)
	flaky := newSimCache()
	mux.HandleFunc("/flaky", func(w http.ResponseWriter, r *http.Request) {
		fail := simResponse{http.StatusInternalServerError, "500 Internal Server Error (transient)"}
		if !vulnerable {
			fail.write(w, "MISS")
			return
		}
		flaky.serveCached(w, r.URL.Path, func() simResponse { return fail })
	})
}

// collisionVictimPath matches the random single-segment paths ("/cd" + 16 hex)
// the key-collision probe plants and reads back.
var collisionVictimPath = regexp.MustCompile(`^/cd[0-9a-f]{16}$`)

// rawPathFixtures serve requests whose raw path matters. Two origins share
// one server, split by directory so each can have the routing its challenge
// needs:
//
//	/static/*  the origin decodes fully and resolves "../" before routing
//	           (cache-deception-static-directory / -normalization)
//	/assets/*  the origin routes the raw path, no resolving
//	           (cache-poisoning-key-collision)
type rawPathFixtures struct {
	vulnerable bool
	me         *simCache
	collide    *simCache
}

func newRawPathFixtures(vulnerable bool) *rawPathFixtures {
	return &rawPathFixtures{vulnerable: vulnerable, me: newSimCache(), collide: newSimCache()}
}

// meBody is /me's authenticated payload, scoped to the caller's token.
func meBody(r *http.Request) simResponse {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		return simResponse{http.StatusUnauthorized, "unauthorized"}
	}
	return simResponse{http.StatusOK, fmt.Sprintf(`{"email": "%s@example.com", "session_token": "%s"}`, token, token)}
}

// serveMe serves /me. Reached by its own path it is private and uncached.
// Reached through a /static/ traversal, a vulnerable cache applies its
// "cache everything under /static/" rule to the raw path and stores it; the
// fixed cache resolves the path first, so it sees /me and doesn't.
func (f *rawPathFixtures) serveMe(w http.ResponseWriter, r *http.Request, viaStatic bool) {
	if !(f.vulnerable && viaStatic) {
		w.Header().Set("Cache-Control", "private, no-store")
		meBody(r).write(w, "BYPASS")
		return
	}
	f.me.serveCached(w, r.URL.RequestURI(), func() simResponse { return meBody(r) })
}

// staticDir is the /static/* origin: it percent-decodes until stable, then
// resolves "." / ".." before routing — so a double-encoded separator
// (..%252f) still ends up as a real traversal.
func (f *rawPathFixtures) staticDir(w http.ResponseWriter, r *http.Request) {
	decoded := r.URL.Path
	for {
		next, err := url.PathUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}
	switch resolved := path.Clean(decoded); {
	case resolved == "/me":
		f.serveMe(w, r, true)
	case strings.HasPrefix(resolved, "/static/"):
		_, _ = w.Write([]byte("// static asset contents"))
	default:
		http.NotFound(w, r)
	}
}

// collision is the /assets/* origin, plus the random victim paths: it routes
// on the raw path (anything under /assets/ is a static bundle), behind a
// cache that, when vulnerable, resolves "../" before computing its key — so
// /assets/x/../../<victim> is stored under /<victim>.
func (f *rawPathFixtures) collision(w http.ResponseWriter, r *http.Request) {
	rawPath := r.URL.Path
	key := rawPath
	if f.vulnerable {
		key = path.Clean(rawPath)
	}
	f.collide.serveCached(w, key, func() simResponse {
		if strings.HasPrefix(rawPath, "/assets/") {
			return simResponse{http.StatusOK, "// asset bundle for " + rawPath}
		}
		return simResponse{http.StatusNotFound, "not found"}
	})
}
