package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

// argvioAPIKey is cache-detective's public_ingest-scoped Argvio API key, selecting the
// "cache-detective" tenant its usage analytics land in. It only allows sending usage
// data, so it is safe to embed.
const argvioAPIKey = "argv_live_pub_oK6l-pEvW4ar74Jc09AIS78RjGINNDGK" //nolint:gosec // ingest-only key, not a secret

var (
	sqaOptOut    bool
	otelShutdown func(context.Context) error
	toolVersion  string
)

var name = "cache-detective"

func NewRootCmd(projectVersion, commit, date string) (cmd *cobra.Command) {
	toolVersion = projectVersion
	var rootCmd = &cobra.Command{
		Use:     name,
		Version: projectVersion + " (commit=" + commit + ", built=" + date + ")",
		Short:   "HTTP cache & CDN behavior analysis CLI",
		Long: `cache-detective analyzes already-deployed, live applications/URLs to determine
whether a response is cacheable per HTTP semantics, whether it is actually
being cached, and how the fronting CDN/reverse proxy behaves with respect
to cache keys, Vary handling, and cache-related security issues.`,
		// OpenTelemetry stays for observability (scan and check spans and
		// timings); usage analytics go to Argvio, see telemetryx.Instrument.
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !sqaOptOut {
				otelShutdown, _ = telemetryx.New(cmd.Context(), name, projectVersion, telemetryx.WithCommit(commit), telemetryx.WithBuildDate(date))
			}
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			shutdownOTel(cmd.Context())
		},
	}

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(diffCmd)

	rootCmd.PersistentFlags().BoolVarP(&sqaOptOut, "sqa-opt-out", "", false, "Opt out of sending anonymous usage statistics and crash reports to help improve the tool")

	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute(projectVersion, commit, date string) {
	c := NewRootCmd(projectVersion, commit, date)
	argvioShutdown := telemetryx.Instrument(c, projectVersion, argvioAPIKey)
	defer func() {
		_ = argvioShutdown(context.Background())
		shutdownOTel(context.Background())
	}()

	if err := telemetryx.Execute(c); err != nil {
		_ = argvioShutdown(context.Background())
		shutdownOTel(context.Background())

		fmt.Fprintln(os.Stderr, err)
		// nolint: gocritic // false positive
		os.Exit(1)
	}
}

// shutdownOTel flushes the OpenTelemetry pipeline once, if one was started.
func shutdownOTel(ctx context.Context) {
	if otelShutdown != nil {
		_ = otelShutdown(ctx)
		otelShutdown = nil
	}
}
