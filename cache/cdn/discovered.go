package cdn

import "sync"

// DelimiterDiscrepancy records one character the delimiter mapper (§5)
// found origin and cache disagree on as a path delimiter. In the origin-only
// direction the origin truncates its route there and serves the undelimited
// resource while a fronting cache keys on the verbatim request path: the cache
// stores the origin's real (possibly authenticated) response under a distinct,
// attacker-chosen URL (cache deception). In the cache-only direction the cache
// truncates its key at the character while the origin routes on the full path:
// a response the origin returns for the delimited URL is stored under — and
// replayed for — the undelimited resource's key (cache poisoning).
type DelimiterDiscrepancy struct {
	// Delimiter is the inserted character sequence, as it was sent on the
	// wire (e.g. ";", "$", or the literal percent-encoding "%00").
	Delimiter string
	// OriginOnly is true when the origin truncated its route at Delimiter
	// (the baseline/suffix/insert probe's R2 == R0) while the cache did not.
	OriginOnly bool
	// CacheOnly is true for the reverse direction: the cache truncated its key
	// at Delimiter (a response fetched through the delimited URL was replayed
	// for the undelimited one) while the origin routed on the full path.
	// Exactly one of OriginOnly/CacheOnly is set on a recorded entry.
	CacheOnly bool
	// Cacheable is true when the response served through the delimiter looked
	// cacheable (RFC 9111) — i.e. the discrepancy is a live cache-deception
	// surface, not just a routing curiosity. Always true for a CacheOnly entry,
	// which is only recorded after the cache was observed storing the response.
	Cacheable bool
}

// TargetQuirks is the mapped delimiter/normalization behavior for one target
// origin (scheme://host[:port]), accumulated across the resources probed
// under it during a scan.
type TargetQuirks struct {
	// Origin is the scheme://host[:port] these quirks were observed against.
	Origin string
	// Delimiters are the origin-only path delimiters discovered, deduplicated
	// across every resource probed under Origin.
	Delimiters []DelimiterDiscrepancy
	// OriginNormalizesEncodedTraversal reports whether the origin collapses an
	// encoded dot-segment ("..%2f") back to the undetoured path — nil when the
	// probe didn't run (e.g. a root path with no segment to pivot on). An
	// origin that normalizes while a fronting cache keys on the verbatim
	// detour path is the "normalize before vs. after cache rules" discrepancy.
	OriginNormalizesEncodedTraversal *bool
	// OriginNormalizesTraversal is the same, for a plain unencoded "../"
	// dot-segment.
	OriginNormalizesTraversal *bool
	// CacheEncodedTraversal is the measured order in which the fronting cache
	// normalizes an encoded dot-segment ("..%2f") relative to applying its
	// cache rules and building the key — NormalizationUnknown when the probe
	// didn't run or couldn't observe the cache (no HIT signal, resource not
	// cached). Only probed where the origin itself normalizes the form.
	CacheEncodedTraversal NormalizationOrder
	// CacheTraversal is the same, for a plain unencoded "../" dot-segment.
	CacheTraversal NormalizationOrder
}

// DiscoveredQuirks is the process-wide store of per-origin delimiter and
// normalization behavior mapped during a scan, so a later check — or a later
// resource under the same origin — can reuse a result instead of re-probing.
// Writes are concurrency-safe: the engine runs per-resource checks in
// parallel.
var DiscoveredQuirks = NewQuirkStore()

// QuirkStore is a concurrency-safe map of target origin to its mapped
// TargetQuirks. Use the package-level DiscoveredQuirks for normal scans;
// construct a private one with NewQuirkStore in tests that need isolation.
type QuirkStore struct {
	mu sync.Mutex
	m  map[string]*TargetQuirks
}

// NewQuirkStore returns an empty QuirkStore.
func NewQuirkStore() *QuirkStore {
	return &QuirkStore{m: make(map[string]*TargetQuirks)}
}

// Record merges q into the store under q.Origin: new delimiters are appended
// (deduplicated by Delimiter), and each non-nil normalization flag overwrites
// the stored one. Origin normalization behavior is largely path-independent,
// so the latest observation wins; delimiter behavior can differ per route, so
// it accumulates as a union across the origin's resources.
func (s *QuirkStore) Record(q TargetQuirks) {
	if q.Origin == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.m[q.Origin]
	if !ok {
		entry = &TargetQuirks{Origin: q.Origin}
		s.m[q.Origin] = entry
	}
	for _, d := range q.Delimiters {
		if !containsDelimiter(entry.Delimiters, d) {
			entry.Delimiters = append(entry.Delimiters, d)
		}
	}
	if q.OriginNormalizesEncodedTraversal != nil {
		v := *q.OriginNormalizesEncodedTraversal
		entry.OriginNormalizesEncodedTraversal = &v
	}
	if q.OriginNormalizesTraversal != nil {
		v := *q.OriginNormalizesTraversal
		entry.OriginNormalizesTraversal = &v
	}
	if q.CacheEncodedTraversal != NormalizationUnknown {
		entry.CacheEncodedTraversal = q.CacheEncodedTraversal
	}
	if q.CacheTraversal != NormalizationUnknown {
		entry.CacheTraversal = q.CacheTraversal
	}
}

// Lookup returns a copy of the quirks recorded for origin, and whether any
// were. The returned value is a deep-enough copy that mutating its slice or
// pointers won't touch the store.
func (s *QuirkStore) Lookup(origin string) (TargetQuirks, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.m[origin]
	if !ok {
		return TargetQuirks{}, false
	}
	out := TargetQuirks{
		Origin:                entry.Origin,
		CacheEncodedTraversal: entry.CacheEncodedTraversal,
		CacheTraversal:        entry.CacheTraversal,
	}
	if len(entry.Delimiters) > 0 {
		out.Delimiters = append([]DelimiterDiscrepancy(nil), entry.Delimiters...)
	}
	if entry.OriginNormalizesEncodedTraversal != nil {
		v := *entry.OriginNormalizesEncodedTraversal
		out.OriginNormalizesEncodedTraversal = &v
	}
	if entry.OriginNormalizesTraversal != nil {
		v := *entry.OriginNormalizesTraversal
		out.OriginNormalizesTraversal = &v
	}
	return out, true
}

// containsDelimiter reports whether list already holds an entry for the same
// delimiter in the same direction (a character can be origin-only on one route
// and cache-only on another).
func containsDelimiter(list []DelimiterDiscrepancy, delim DelimiterDiscrepancy) bool {
	for _, d := range list {
		if d.Delimiter == delim.Delimiter && d.CacheOnly == delim.CacheOnly {
			return true
		}
	}
	return false
}
