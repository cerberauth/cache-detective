<div align="center">

# cache-detective

**A CLI that analyzes live URLs for HTTP cacheability, live cache state, CDN behavior, and cache-related security issues.**

[![Join Discord](https://img.shields.io/discord/1242773130137833493?label=Discord&style=for-the-badge)](https://www.cerberauth.com/community)
[![Build](https://img.shields.io/github/actions/workflow/status/cerberauth/cache-detective/ci.yml?branch=main&label=build&style=for-the-badge)](https://github.com/cerberauth/cache-detective/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/cerberauth/cache-detective?sort=semver&style=for-the-badge)](https://github.com/cerberauth/cache-detective/releases)
[![Coverage](https://img.shields.io/codecov/c/gh/cerberauth/cache-detective?style=for-the-badge)](https://codecov.io/gh/cerberauth/cache-detective)
[![GoDoc](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=for-the-badge)](https://godoc.org/github.com/cerberauth/cache-detective)
[![Stars](https://img.shields.io/github/stars/cerberauth/cache-detective?style=for-the-badge)](https://github.com/cerberauth/cache-detective)
[![License](https://img.shields.io/github/license/cerberauth/cache-detective?style=for-the-badge)](https://github.com/cerberauth/cache-detective/blob/main/LICENSE)

</div>

---

`cache-detective` analyzes already-deployed, live applications/URLs to determine:

- Whether a response **is cacheable** per HTTP semantics (RFC 9111) and CDN-specific behavior
- Whether a response **is actually being cached** (live HIT/MISS/STALE state)
- How the fronting CDN/reverse proxy **behaves** with respect to cache keys, `Vary` handling, and cache-related security issues (poisoning / deception surface)

> **Disclaimer:** The `--aggressive` cache poisoning / cache deception probes are intended for authorised security testing, penetration testing, and educational purposes only. Never test systems you do not own or have explicit written permission to test.

---

## Features

| Feature | Flag |
|---------|:---:|
| Single-URL, list-file, sitemap, `.har`, or same-origin crawl input | ✓ |
| Cache-Control/Expires/Pragma/Vary parsing (RFC 9111) | ✓ |
| Authenticated-but-cacheable misconfiguration detection | ✓ |
| Live HIT/MISS/STALE/EXPIRED/BYPASS state detection | ✓ |
| CDN/reverse-proxy fingerprinting (CNAME + Server/Via) | ✓ |
| Declared vs. observed cache-key (`Vary`) analysis | ✓ |
| Unkeyed header injection probing | `--aggressive` |
| Cache deception (path confusion / static-extension) probing | `--aggressive` |
| Error-response caching probing | `--aggressive` |
| Response splitting probing | `--aggressive` |
| Conditional-request (304) validation, redirect caching | ✓ |
| JSON output + drift detection between two scans (`diff`) | ✓ |

---

## Supported CDNs & servers

Live cache-state detection ([§2](#architecture)) and CDN fingerprinting ([§3](#architecture)) read from one extensible signature table, [`cache/cdn/registry.go`](./cache/cdn/registry.go). Each entry knows the header that carries that CDN's own HIT/MISS verdict, and what to match against `Server`/`Via`/CNAME to identify it:

| CDN / server | Cache-status header | Server/Via fingerprint | CNAME apex |
|---|---|---|---|
| Cloudflare | `CF-Cache-Status` | `cloudflare` | `cloudflare.net` |
| Fastly | `X-Cache` | `fastly` (Server), `varnish` (Via) | `fastly.net`, `fastlylb.net` |
| Akamai | `X-Cache` | `akamaighost` | `akamaiedge.net`, `akamaitechnologies.com`, `akamai.net` |
| Amazon CloudFront | `X-Cache` | `cloudfront` (Via) | `cloudfront.net` |
| Varnish | `X-Cache` | `varnish` (Via) | — |
| Vercel | `X-Vercel-Cache` | `vercel` | `vercel-dns.com`, `vercel.app` |
| Netlify | `X-Nf-Request-Id` (presence only — Netlify emits no HIT/MISS verdict, see fallback below) | `netlify` | `netlify.app`, `netlifyglobalcdn.com` |
| Pantheon | `X-Cache` | `pantheon` | `pantheonsite.io` |

Several entries share `X-Cache` with different value vocabularies (e.g. Fastly's `hit`/`miss`/`pass` vs. Akamai's `TCP_HIT`/`TCP_MISS`/...) — `Detect` disambiguates by fingerprinting the CDN from `Server`/`Via` (or CNAME) *first*, then reads that CDN's own header, rather than guessing from the header value alone.

### Fallback for everything else

A server or CDN not in the table above isn't a dead end — cache-detective falls back through three layers, from most to least specific, and every check that reports a state records which layer produced it:

1. **Generic header conventions** — an unrecognized `Server-Timing: cdn-cache; desc=HIT` header (a convention several CDNs are converging on), or a bare `X-Cache: HIT`/`MISS` from a reverse proxy that isn't in the registry.
2. **Timing/Age heuristic** ([§2](#architecture), `cache/checks/livestate`) — when no header gives an explicit verdict at all: a non-decreasing `Age` header across the `--requests` samples, or a repeat request answered meaningfully faster than the first, both suggest *something* is caching the response, even anonymously. This is flagged as a best-effort inference (`TimingHeuristic`/"no explicit cache-status header" in the report), never presented as equivalent to a header-based verdict.
3. **No signal** — if none of the above apply, the resource is reported as `UNKNOWN` rather than guessed.

**Missing your CDN or server?** [Open an issue](https://github.com/cerberauth/cache-detective/issues/new) with the `Server`/`Via`/cache-status headers and CNAME chain it emits — adding a new entry to `Registry` is a data change, not a code change, so most requests are a small PR.

---

## Installation

### Using `go install`:

```sh
go install github.com/cerberauth/cache-detective@latest
```

Requires Go 1.24 or later.

### Using Homebrew:

```sh
brew install cerberauth/tap/cache-detective
```

### Using Docker:

```sh
docker run --rm ghcr.io/cerberauth/cache-detective scan --url https://example.com/
```

See [Docker](#docker) below for volume mounts, Compose, and CI usage.

### From source:

```sh
git clone https://github.com/cerberauth/cache-detective.git
cd cache-detective
go build -o cache-detective .
```

Verify the installation:

```sh
cache-detective --version
```

---

## Docker

Images are published on every release. The entrypoint is the `cache-detective` binary, so any CLI command works after the image name:

```sh
docker run --rm ghcr.io/cerberauth/cache-detective scan --url https://example.com/
```

Also available at `cerberauth/cache-detective` on Docker Hub.

Commands that read a local file (`--list`, `--har`) need that file inside the container. Mount the containing directory as a volume and reference the in-container path:

```sh
docker run --rm -v "$(pwd)":/data ghcr.io/cerberauth/cache-detective \
  scan --list /data/urls.txt
```

When probing a server running in another container, join its network:

```sh
docker run --rm --network container:api ghcr.io/cerberauth/cache-detective \
  scan --url http://localhost:8080/
```

See the [Docker guide](./docs/docker.mdx) for Compose usage and building the dev image from source.

---

## CLI Usage

```
cache-detective [command] [flags]

Commands:
  scan      Analyze cacheability and live cache behavior for one or more URLs
  diff      Compare two JSON scans to detect cache-config drift
```

The resource list for `scan` is resolved from exactly one of `--url`, `--list`, `--sitemap`, `--har`, or `--crawl`.

### scan

Probes one or more URLs to determine:

- whether each response is cacheable per HTTP semantics (RFC 9111)
- whether it is actually being cached (live HIT/MISS/STALE state)
- how the fronting CDN/reverse proxy identifies itself and handles the cache key (`Vary`, query strings, cookies, custom headers)

```sh
cache-detective scan (--url <url> | --list <file> | --sitemap <url> | --har <file> | --crawl) [flags]
```

| Flag | Description |
|------|-------------|
| `--url` | Single target URL to scan |
| `--list` | Path to a newline-delimited list of URLs |
| `--sitemap` | URL of a sitemap.xml to scan |
| `--har` | Path to a `.har` file to import GET/HEAD requests from |
| `--crawl` | Crawl same-origin links starting from `--url` instead of scanning it alone |
| `--path-prefix` | Restrict `--crawl` to URLs under this path prefix |
| `--max-pages` | Maximum pages to discover with `--crawl` (default `50`) |
| `--respect-robots` | Honor `robots.txt` Disallow rules for `"*"` during `--crawl` (default `true`) |
| `--method` | HTTP method to test (default `GET`) |
| `--header` | Custom request header `Name=Value` (repeatable) |
| `--cookie` | Cookie `name=value` to send with every request (repeatable) |
| `--bearer` | Bearer token for authenticated cache testing |
| `--requests` | Probe requests issued per resource for live cache-state detection (default `3`) |
| `--interval` | Delay between consecutive probe requests to the same resource (default `500ms`) |
| `--timeout` | Per-request timeout (default `15s`) |
| `--aggressive` | Enable cache poisoning/deception probing — opt-in since a positive result means the check just demonstrated it can plant content in a shared cache other users may be served |
| `--max-aggressive-requests` | Hard cap on extra probe requests per resource for `--aggressive` checks (and the read-only vary-key check) (default `10`) |
| `--max-concurrency` | Maximum concurrent checks (default: number of CPUs) |
| `--max-resource-concurrency` | Maximum concurrent resources per check (default: number of CPUs) |
| `--format` | Terminal display format |
| `--no-color` | Disable ANSI colors in terminal output |
| `--quiet` | Suppress terminal display of the report |
| `--output` | File path to additionally write the report to |
| `--output-format` | Format for `--output` (default `json`) |
| `--show-all-findings` | Show every finding on stdout, not just vulnerable ones |
| `--report-url` | HTTP endpoint to POST the report to |
| `--report-header` | Additional HTTP headers for the report transport (`key=value`, repeatable) |
| `--report-format` | Format for `--report-url` (default `json`) |

```sh
# Single URL
cache-detective scan --url https://example.com/

# A list file, a sitemap, or a .har import
cache-detective scan --list urls.txt
cache-detective scan --sitemap https://example.com/sitemap.xml
cache-detective scan --har session.har

# Same-origin crawl
cache-detective scan --url https://example.com/ --crawl --path-prefix /blog

# Authenticated cache testing
cache-detective scan --url https://example.com/account --bearer $TOKEN

# Cache poisoning / cache deception probing (opt-in, see "Safety defaults" below)
cache-detective scan --url https://example.com/ --aggressive

# JSON output for CI, and drift detection between two scans over time
cache-detective scan --url https://example.com/ --output-format json --output before.json
cache-detective scan --url https://example.com/ --output-format json --output after.json
cache-detective diff before.json after.json
```

Exits `1` when any check fails.

---

### diff

Compares two scans (each produced via `cache-detective scan --output-format json --output <file>`) over time, reporting findings that newly appeared, disappeared, or changed severity between the two — cache-config drift detection.

```sh
cache-detective diff <before.json> <after.json>
```

```sh
cache-detective diff before.json after.json
```

Exits `1` when any finding was added or changed severity.

---

## Safety defaults

Every check that could pollute a shared cache — unkeyed header injection, cache deception path-confusion, error-response caching, response splitting — is gated behind `--aggressive`. `--max-aggressive-requests` hard-caps extra requests per resource even with `--aggressive` set, and `--respect-robots` (on by default for `--crawl`) honors `robots.txt`.

---

## Architecture

Each numbered section below is one `harnessx.Check` (or a small family of them), living in its own `cache/checks/<name>` package with its own `check.go` (harnessx wiring) + a pure-logic file + `httptest.Server`-backed tests:

| § | Package | What it does |
|---|---------|--------------|
| 1 | `cache/checks/cacheability` | Cache-Control/Expires/Pragma/Vary parsing, RFC 9111 status/method defaults, conflicting-directive and missing-validator findings, plus a split-out `AuthCheck` for the authenticated-but-cacheable security finding |
| 2 | `cache/checks/livestate` | Multi-request HIT/MISS/STALE/EXPIRED/BYPASS detection via the CDN registry, with a timing/Age heuristic fallback |
| 3 | `cache/checks/fingerprint` | CNAME chain resolution + Server/Via matching (via the CDN registry) + multi-tier cache evidence |
| 4 | `cache/checks/varykey` | Declared-`Vary` vs. observed cache-key inclusion for Accept-Encoding/Accept-Language/User-Agent/a custom header |
| 5 | `cache/checks/security` | Unkeyed header injection, cache deception (path confusion / static-extension), error-response caching, response splitting — all `--aggressive`-gated |
| 6 | `cache/checks/consistency` | Conditional-request (304) validation, redirect caching |
| 7 | `cache/crawl` | URL list / sitemap / `.har` import / same-origin crawl with scope + `robots.txt` courtesy, resolved **before** the engine runs |
| 8 | `cache/geo` | `Provider` interface + `NoopProvider` for future multi-region probing — no real geo backend ships in v1 |
| — | `cache/cdn` | The extensible CDN signature table (Cloudflare, Fastly, Akamai, CloudFront, Varnish, Vercel, Netlify, Pantheon, ...) every detection/fingerprint check reads from |
| — | `cache/checkbase` | Shared `ProbeCtx` (the scan-wide config every check reads from `Target.Data`), request-building helpers, and `DiscoveryCheck` |
| — | `cache/probe.go` | `BuildChecks`/`CheckDefs`/`ScanAll` — wires every check into one `harnessx.Engine.Run` |

IP range (ASN/CIDR) matching from §3 is deliberately **not implemented** in v1 — it needs a maintained, licensable dataset. The `Result` shape it would populate is defined now (`fingerprint.Result.IPRangeLookupAvailable`) so a real backend drops in later without reshaping the check.

### Design notes

cache-detective's job is inherently multi-URL (a single URL, a list, a sitemap, a crawl), which shapes a few decisions worth calling out:

- **Every check is `harnessx.ScopePerResource`**, fed by `checkbase.DiscoveryCheck` publishing the resolved URL list as `harnessx.Resource`s. Concurrent multi-URL probing and rate limiting come for free from harnessx's existing per-resource concurrency (`Check.Concurrency` / `WithMaxResourceConcurrency`) rather than a bespoke worker pool.
- **Resolving the resource list (§7) happens before `Engine.Run`**, in the `cache/crawl` package, instead of as a `harnessx.Check` — this keeps the dependency graph flat (every check just depends on `discovery`) and keeps crawl-specific courtesy concerns (`robots.txt`, scope rules) in one place instead of re-solved inside the check DAG.
- **Findings are split across multiple `CheckID`s by severity**, rather than one check emitting observations of mixed severity. harnessx/reportx score a finding from its *check's* `CVSSScore` (set once on `CheckDef`), not per-observation — so, e.g., cacheability's informational findings (conflicting directives, missing validators) live on the `cacheability` check with no CVSS, while the "authenticated response marked cacheable" misconfiguration is its own `authenticated-cacheable` check with real CVSS/CWE/OWASP metadata. Each `Observation.Metadata["severity"]` still carries an advisory severity hint for tooling that reads it directly.

---

## Testing

`go test ./...` — every check package has `httptest.Server`-backed tests, plus pure-logic unit tests for the parsing/analysis functions that don't need a live server.

## What's stubbed vs. solid

Per the project's phased build-out, §1 (cacheability) and §2 (live-state) are the most thoroughly tested; §3–§7 are real, working implementations with test coverage but narrower scope than a mature tool would eventually want (e.g. `varykey` tests four dimensions, not every conceivable header; `crawl`'s HTML link extraction is a regex, not a full parser). §8 (geo) is an interface + no-op only, by design — see above.

## Known limitations

- **Findings carry no per-instance URL/parameter.** reportx's `Finding.URL`/`Finding.Parameter` fields (used by `diff` to identify "the same finding" across two scans) aren't populated by any check yet — the resource a finding came from is only in its Description/Evidence text. Two findings with the same title from the same check against the same resource (e.g. cache deception firing for more than one probed path suffix) are therefore indistinguishable to `diff` today; it only tracks presence and severity per title, not per instance.
- **The §5 security checks are gated inside `Run`, not via `harnessx.SkipDecision`.** `x/reportx/harnessreport`'s bridge turns *every* check-level `Skip` into a reportx Finding (using the check's Name/CVSS as an inert placeholder), with no way to distinguish "explicitly gated off" from "ran and found nothing" or "genuinely vulnerable" in the JSON output. Since the four aggressive-only checks are gated off on every default scan, using `Skip` for that would put four misleading entries in every report's `--output-format json`. See `aggressiveGate`'s doc comment in `cache/checks/security/check.go`.

---

## License

MIT © [CerberAuth](https://www.cerberauth.com/) — see [LICENSE](https://github.com/cerberauth/cache-detective/blob/main/LICENSE) for details.
