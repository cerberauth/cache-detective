package main

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// pathMappingFixtures back the delimiter & normalization discrepancy mapper
// (§5). Each simulates one side of the origin/cache split on a raw path, and
// is routed ahead of the mux (which would redirect a non-clean path):
//
//	/delim-origin  the origin truncates its route at ";" (vulnerable) —
//	               an origin-only delimiter
//	/delim-cache   the cache keys on the path up to ";" (vulnerable) while the
//	               origin routes strictly — a cache-only delimiter
//	/norm-order    the origin resolves "../" and "..%2f"; the cache keys the
//	               verbatim detour path (vulnerable, "normalizes after cache
//	               rules") or the resolved path (fixed, "normalizes before")
type pathMappingFixtures struct {
	vulnerable bool
	delimCache *simCache
	delimOrig  *simCache
	norm       *simCache
}

const (
	delimOriginPath = "/delim-origin"
	delimCachePath  = "/delim-cache"
	normOrderPath   = "/norm-order"
)

func newPathMappingFixtures(vulnerable bool) *pathMappingFixtures {
	return &pathMappingFixtures{vulnerable: vulnerable, delimCache: newSimCache(), delimOrig: newSimCache(), norm: newSimCache()}
}

// handles reports whether r belongs to one of the path-mapping fixtures and
// returns its handler. r.URL.Path is percent-decoded, so cleaning it resolves
// both the plain and the encoded detour back to the fixture's own path.
func (f *pathMappingFixtures) handles(r *http.Request) (http.HandlerFunc, bool) {
	switch {
	case strings.HasPrefix(r.URL.Path, delimOriginPath):
		return f.serveDelimOrigin, true
	case strings.HasPrefix(r.URL.Path, delimCachePath):
		return f.serveDelimCache, true
	case path.Clean(r.URL.Path) == normOrderPath:
		return f.serveNormOrder, true
	}
	return nil, false
}

// served is the fixtures' one cacheable resource body, and notFound the
// response for any path the origin has no route for.
func served(name string) simResponse { return simResponse{http.StatusOK, name + " contents"} }

var notFound = simResponse{http.StatusNotFound, "not found"}

// serveDelimOrigin: when vulnerable, the origin routes on the path up to the
// first ";" (as frameworks that treat ";" as a path-parameter delimiter do), so
// /delim-origin;anything serves the resource. The cache in front keys the raw
// request target, so it would store that under the distinct delimited URL.
func (f *pathMappingFixtures) serveDelimOrigin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=600")
	f.delimOrig.serveCached(w, r.URL.RequestURI(), func() simResponse {
		route := r.URL.Path
		if f.vulnerable {
			route, _, _ = strings.Cut(route, ";")
		}
		if route == delimOriginPath {
			return served("delim-origin")
		}
		return notFound
	})
}

// serveDelimCache: the origin routes strictly, so /delim-cache;anything is a
// 404. When vulnerable the cache drops everything from ";" onward before
// keying, so that 404 is stored under — and replayed for — /delim-cache.
func (f *pathMappingFixtures) serveDelimCache(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=600")
	key := r.URL.RequestURI()
	if f.vulnerable {
		p, q, hasQuery := strings.Cut(key, "?")
		key, _, _ = strings.Cut(p, ";")
		if hasQuery {
			key += "?" + q
		}
	}
	f.delimCache.serveCached(w, key, func() simResponse {
		if r.URL.Path == delimCachePath {
			return served("delim-cache")
		}
		return notFound
	})
}

// serveNormOrder: the origin always resolves dot-segments (decoding "%2f" on
// the way), so every detour reaches the resource. Only the cache differs: the
// vulnerable one keys the verbatim request target and stores each detour under
// its own URL; the fixed one resolves the path first, so a detour is answered
// from the canonical entry.
func (f *pathMappingFixtures) serveNormOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=600")
	key := r.URL.RequestURI()
	if !f.vulnerable {
		key = path.Clean(r.URL.Path)
		if r.URL.RawQuery != "" {
			key += "?" + url.PathEscape(r.URL.RawQuery)
		}
	}
	f.norm.serveCached(w, key, func() simResponse { return served("norm-order") })
}
