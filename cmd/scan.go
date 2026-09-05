package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/harnessx/reporters"
	cobrareportx "github.com/cerberauth/x/cobrax/reportx"
	"github.com/cerberauth/x/reportx/harnessreport"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"

	cache "github.com/cerberauth/cache-detective/cache"
	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/crawl"
)

var (
	scanURL             string
	scanListFile        string
	scanSitemapURL      string
	scanHARFile         string
	scanCrawl           bool
	scanPathPrefix      string
	scanMaxPages        int
	scanRespectRobots   bool
	scanMethod          string
	scanHeaders         []string
	scanCookies         []string
	scanBearer          string
	scanRequestCount    int
	scanRequestInterval time.Duration
	scanTimeout         time.Duration
	scanAggressive      bool
	scanMaxAggressive   int
	scanMaxConcurrency  int
	scanMaxResourceConc int
)

var scanOtelName = "github.com/cerberauth/cache-detective/cmd/scan"

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Analyze cacheability and live cache behavior for one or more URLs",
	Long: `Probes one or more URLs to determine:

  • whether each response is cacheable per HTTP semantics (RFC 9111)
  • whether it is actually being cached (live HIT/MISS/STALE state)
  • how the fronting CDN/reverse proxy identifies itself and handles the
    cache key (Vary, query strings, cookies, custom headers)

The resource list is resolved from exactly one of --url, --list, --sitemap,
--har, or --crawl.

Security-focused checks (cache poisoning / cache deception probing) are
opt-in via --aggressive, since a positive result means the check just
demonstrated it can plant content in a shared cache other users may be
served. --max-aggressive-requests hard-caps how many extra requests any one
aggressive check issues per resource, even with --aggressive set.

Use only against systems you own or have explicit written permission to test.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		resources, target, err := resolveResources(ctx)
		if err != nil {
			return err
		}
		if len(resources) == 0 {
			return fmt.Errorf("no resources to scan")
		}

		pctx := checkbase.ProbeCtx{
			Probe:                 probe.New(),
			Method:                scanMethod,
			Headers:               parseHeaders(scanHeaders),
			Cookies:               parseCookies(scanCookies),
			BearerToken:           scanBearer,
			RequestCount:          scanRequestCount,
			RequestInterval:       scanRequestInterval,
			Timeout:               scanTimeout,
			Aggressive:            scanAggressive,
			MaxAggressiveRequests: scanMaxAggressive,
			Resources:             resources,
		}

		sinks, cleanup, err := cobrareportx.SinksFromFlags(cmd)
		if err != nil {
			return err
		}
		defer cleanup()

		reportxReporter := harnessreport.New(ctx, harnessreport.Config{
			ToolName:    name,
			ToolVersion: toolVersion,
			Title:       "Cache Behavior Scan",
			Sinks:       sinks,
			CheckDefs:   cache.CheckDefs(),
		})

		otelReporter, _ := reporters.NewOTelReporter(
			ctx,
			otel.Tracer(scanOtelName),
			telemetryx.GetMeterProvider().Meter(scanOtelName),
			reporters.WithPrefix("cache.scan"),
		)

		summary, err := cache.ScanAll(ctx, target, cache.ScanOptions{
			ProbeCtx:               pctx,
			Reporters:              []harnessx.Reporter{otelReporter, reportxReporter},
			MaxConcurrency:         scanMaxConcurrency,
			MaxResourceConcurrency: scanMaxResourceConc,
		})
		if err != nil {
			return fmt.Errorf("scanning: %w", err)
		}

		if err := reportxReporter.Err(); err != nil {
			return fmt.Errorf("reporting: %w", err)
		}

		if summary.Failed > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func resolveResources(ctx context.Context) ([]checkbase.ResourceSpec, string, error) {
	set := 0
	for _, v := range []string{scanURL, scanListFile, scanSitemapURL, scanHARFile} {
		if v != "" {
			set++
		}
	}
	if scanCrawl {
		set++
	}
	if set != 1 {
		return nil, "", fmt.Errorf("exactly one of --url, --list, --sitemap, --har, --crawl must be set")
	}

	switch {
	case scanListFile != "":
		specs, err := crawl.FromListFile(scanListFile)
		if err != nil {
			return nil, "", err
		}
		return specs, scanListFile, nil
	case scanSitemapURL != "":
		specs, err := crawl.FromSitemap(ctx, http.DefaultClient, scanSitemapURL)
		if err != nil {
			return nil, "", err
		}
		return specs, scanSitemapURL, nil
	case scanHARFile != "":
		specs, err := crawl.FromHAR(scanHARFile)
		if err != nil {
			return nil, "", err
		}
		return specs, scanHARFile, nil
	case scanCrawl:
		found, err := crawl.Crawl(ctx, scanURL, crawl.Options{
			Scope:         crawl.Scope{PathPrefix: scanPathPrefix},
			MaxPages:      scanMaxPages,
			RespectRobots: scanRespectRobots,
		})
		if err != nil {
			return nil, "", err
		}
		return crawl.FromURLs(found), scanURL, nil
	default:
		return []checkbase.ResourceSpec{{ID: "root", URL: scanURL}}, scanURL, nil
	}
}

func parseHeaders(raw []string) map[string][]string {
	out := map[string][]string{}
	for _, h := range raw {
		k, v, ok := cutKV(h)
		if !ok {
			continue
		}
		out[k] = append(out[k], v)
	}
	return out
}

func parseCookies(raw []string) []checkbase.Cookie {
	out := make([]checkbase.Cookie, 0, len(raw))
	for _, c := range raw {
		k, v, ok := cutKV(c)
		if !ok {
			continue
		}
		out = append(out, checkbase.Cookie{Name: k, Value: v})
	}
	return out
}

func cutKV(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func init() {
	scanCmd.Flags().StringVar(&scanURL, "url", "", "Single target URL to scan")
	scanCmd.Flags().StringVar(&scanListFile, "list", "", "Path to a newline-delimited list of URLs")
	scanCmd.Flags().StringVar(&scanSitemapURL, "sitemap", "", "URL of a sitemap.xml to scan")
	scanCmd.Flags().StringVar(&scanHARFile, "har", "", "Path to a .har file to import GET/HEAD requests from")
	scanCmd.Flags().BoolVar(&scanCrawl, "crawl", false, "Crawl same-origin links starting from --url instead of scanning it alone")
	scanCmd.Flags().StringVar(&scanPathPrefix, "path-prefix", "", "Restrict --crawl to URLs under this path prefix")
	scanCmd.Flags().IntVar(&scanMaxPages, "max-pages", 50, "Maximum pages to discover with --crawl")
	scanCmd.Flags().BoolVar(&scanRespectRobots, "respect-robots", true, "Honor robots.txt Disallow rules for \"*\" during --crawl")
	scanCmd.Flags().StringVar(&scanMethod, "method", "GET", "HTTP method to test")
	scanCmd.Flags().StringArrayVar(&scanHeaders, "header", nil, "Custom request header \"Name=Value\" (repeatable)")
	scanCmd.Flags().StringArrayVar(&scanCookies, "cookie", nil, "Cookie \"name=value\" to send with every request (repeatable)")
	scanCmd.Flags().StringVar(&scanBearer, "bearer", "", "Bearer token for authenticated cache testing")
	scanCmd.Flags().IntVar(&scanRequestCount, "requests", 3, "Probe requests issued per resource for live cache-state detection")
	scanCmd.Flags().DurationVar(&scanRequestInterval, "interval", 500*time.Millisecond, "Delay between consecutive probe requests to the same resource")
	scanCmd.Flags().DurationVar(&scanTimeout, "timeout", 15*time.Second, "Per-request timeout")
	scanCmd.Flags().BoolVar(&scanAggressive, "aggressive", false, "Enable cache poisoning/deception probing (§5) — opt-in since it intentionally probes for exploitable cache behavior")
	scanCmd.Flags().IntVar(&scanMaxAggressive, "max-aggressive-requests", 10, "Hard cap on extra probe requests per resource for --aggressive checks (and the read-only vary-key check)")
	scanCmd.Flags().IntVar(&scanMaxConcurrency, "max-concurrency", 0, "Maximum concurrent checks (default: number of CPUs)")
	scanCmd.Flags().IntVar(&scanMaxResourceConc, "max-resource-concurrency", 0, "Maximum concurrent resources per check (default: number of CPUs)")

	cobrareportx.RegisterFormatFlags(scanCmd)
	cobrareportx.RegisterTransportFlags(scanCmd)
}
