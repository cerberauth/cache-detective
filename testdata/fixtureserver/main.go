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
	"log"
	"net/http"
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

	log.Printf("fixtureserver listening on %s (vulnerable=%v)", *addr, *vulnerable)
	log.Fatal(http.ListenAndServe(*addr, mux)) //nolint:gosec // G114: fixed-duration CI fixture, not a production server
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
