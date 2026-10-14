package cdn

import "sync"

// DelimiterDiscrepancy records one character the delimiter mapper (§5)
// found the origin treats as a path delimiter — truncating its route there
// and serving the undelimited resource — while a fronting cache keys on the
// verbatim request path. That split is the foundation of both cache-key
// poisoning and cache deception: the cache stores the origin's real
// (possibly authenticated) response under a distinct, attacker-chosen URL.
type DelimiterDiscrepancy struct {
	// Delimiter is the inserted character sequence, as it was sent on the
	// wire (e.g. ";", "$", or the literal percent-encoding "%00").
	Delimiter string
	// OriginOnly is true when the origin truncated its route at Delimiter
	// (the baseline/suffix/insert probe's R2 == R0) — the discrepancy this
	// store exists to record. Always true for a recorded entry today; the
	// field is explicit so a future reverse-direction finding (cache-only
	// delimiter) has a home.
	OriginOnly bool
	// Cacheable is true when the response served through the delimiter looked
	// cacheable (RFC 9111) — i.e. the discrepancy is a live cache-deception
	// surface, not just a routing curiosity.
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
		if !containsDelimiter(entry.Delimiters, d.Delimiter) {
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
	out := TargetQuirks{Origin: entry.Origin}
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

func containsDelimiter(list []DelimiterDiscrepancy, delim string) bool {
	for _, d := range list {
		if d.Delimiter == delim {
			return true
		}
	}
	return false
}
