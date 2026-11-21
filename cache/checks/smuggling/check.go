// Package smuggling implements the optional request-smuggling/desync
// module (issue #18): CL.TE/TE.CL/TE.TE differential timing probes, plus
// HTTP/2-downgrade and client-side-desync (CSD) precondition advisories
// (Kettle, "HTTP Desync Attacks", 2019; "Browser-Powered Desync Attacks",
// 2022; "HTTP/1.1 must die", 2025).
//
// This module is explicitly higher blast-radius than the rest of §5
// (cache/checks/security): every other aggressive check confirms a clean
// HTTP exchange was poisoned or deceived, never leaving anything in an
// ambiguous state. A desync timing probe, by its nature, deliberately sends
// a request a conforming server should reject and watches whether a
// connection is left hanging — on a genuinely vulnerable target, that hang
// is the backend sitting mid-request, waiting for bytes that will never
// arrive. It is gated behind checkbase.ProbeCtx.EnableSmuggling *in addition
// to* Aggressive, so it stays off even under --aggressive unless explicitly
// requested, and every raw connection is closed with a bounded read
// deadline (rawProbeTimeout) so a hang here can never exceed that window.
package smuggling

import (
	"context"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

const (
	securityTag  = "security"
	smugglingTag = "request-smuggling"

	cvssSmuggling  = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H"
	cweSmuggling   = "CWE-444"
	owaspMisconfig = "A05:2021-Security Misconfiguration"

	// schemeHTTPS is shared across the package's TLS-vs-plaintext
	// branching (dialRaw, the H2-downgrade precondition's own ALPN dial).
	schemeHTTPS = "https"
)

// Def describes the request-smuggling/desync check.
var Def = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDSmuggling),
	Name:        "Request Smuggling / Desync",
	Description: "Opt-in, higher-blast-radius module: CL.TE/TE.CL/TE.TE differential timing probes over a fresh raw connection (a confirmed delay against a measured baseline means a conforming party stopped reading where another kept going — likely request smuggling, not a destructive confirmation of it), plus HTTP/2-downgrade and client-side-desync precondition advisories. Requires --aggressive and --enable-smuggling together.",
	Tags:        []string{securityTag, smugglingTag},
	DependsOn:   []string{string(checkbase.CheckIDDiscovery)},
	CVSSVector:  cvssSmuggling,
	CVSSScore:   8.6,
	CWEID:       cweSmuggling,
	OWASP:       owaspMisconfig,
}

// Check is the registered harnessx.Check for Def.
var Check = checkdef.NewResourceCheck(Def, run)

// rawProbeTimeout bounds how long any one raw timing probe (and the TLS
// handshake used by the HTTP/2-downgrade precondition) waits for a
// response, so a genuinely hung backend never stalls the scan — or holds a
// connection open — longer than this. Generous enough for a slow-but-honest
// origin to still answer normally; Kettle's own write-ups use a similarly
// short window. A var, not a const, so tests can shrink it instead of
// spending real wall-clock seconds proving a hang was detected.
var rawProbeTimeout = 5 * time.Second

// smugglingGate reports whether the module should run: both Aggressive and
// EnableSmuggling, unlike every other §5 check (which needs Aggressive
// alone) — see checkbase.ProbeCtx.EnableSmuggling's doc comment. Checked
// inside Run rather than wired as a harnessx.SkipDecision, for the same
// reporting reason the rest of §5 does — see security.aggressiveGate's doc
// comment in cache/checks/security/check.go.
func smugglingGate(target harnessx.Target) bool {
	pctx, ok := target.Data.(*checkbase.ProbeCtx)
	return ok && pctx.Aggressive && pctx.EnableSmuggling
}

func run(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !smugglingGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)
	budget := pctx.MaxAggressiveRequests

	var obs []harnessx.Observation

	baselineExchange, baseline, err := measureBaseline(ctx, pctx, resource.URL)
	if err == nil {
		obs = append(obs, probeDesyncTiming(resource, baseline, &budget)...)
	}

	if ob, found := probeHTTP2Downgrade(resource); found {
		obs = append(obs, ob)
	}
	// Reuses baselineExchange rather than issuing its own plain GET: it
	// only needs to know the baseline was a redirect before deciding
	// whether the extra raw round-trip below is worth spending at all.
	if err == nil {
		if ob, found := probeClientSideDesync(resource, baselineExchange); found {
			obs = append(obs, ob)
		}
	}

	return harnessx.Result{Observations: obs}, nil
}

// measureBaseline times a single plain, well-formed request through the
// normal probe client — the "honest" reference point every timing probe
// below is compared against, so a target that's merely slow overall doesn't
// get misread as desync-vulnerable. The Exchange itself is also returned,
// so probeClientSideDesync can reuse it instead of issuing its own
// redundant plain request just to check the status code.
func measureBaseline(ctx context.Context, pctx *checkbase.ProbeCtx, resourceURL string) (checkbase.Exchange, time.Duration, error) {
	req, err := checkbase.NewRequest(ctx, resourceURL, pctx, nil)
	if err != nil {
		return checkbase.Exchange{}, 0, err
	}
	start := time.Now()
	ex, err := checkbase.Do(ctx, pctx, req)
	if err != nil {
		return checkbase.Exchange{}, 0, err
	}
	return ex, time.Since(start), nil
}

// desyncDelayed reports whether elapsed, measured against baseline,
// signals a hung backend: either it ran out the full probe window (the
// strongest signal — nothing came back at all), or it took far longer than
// an honest request to the same target ever would.
func desyncDelayed(elapsed, baseline time.Duration) bool {
	// 90% of the configured window, not a fixed margin subtracted from it:
	// a fixed margin (e.g. "timeout - 500ms") goes to zero or negative once
	// rawProbeTimeout itself is shrunk below that margin — as tests do —
	// making this always true regardless of the actual measurement.
	if elapsed >= rawProbeTimeout*9/10 {
		return true
	}
	// Same reasoning for the relative-to-baseline margin: scale it by
	// rawProbeTimeout instead of a fixed 1s, which would dwarf a shrunk
	// test timeout and make this branch unreachable in a fast test.
	margin := rawProbeTimeout / 5
	return elapsed > baseline*3+margin
}
