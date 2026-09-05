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
	"log"
	"net/http"
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

	log.Printf("fixtureserver listening on %s (vulnerable=%v)", *addr, *vulnerable)
	log.Fatal(http.ListenAndServe(*addr, mux)) //nolint:gosec // G114: fixed-duration CI fixture, not a production server
}
