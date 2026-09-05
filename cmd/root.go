package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

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
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !sqaOptOut {
				otelShutdown, _ = telemetryx.New(cmd.Context(), name, projectVersion, telemetryx.WithCommit(commit), telemetryx.WithBuildDate(date))
			}
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if otelShutdown != nil {
				_ = otelShutdown(cmd.Context())
				otelShutdown = nil
			}
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
	defer func() {
		if otelShutdown != nil {
			_ = otelShutdown(context.Background())
			otelShutdown = nil
		}
	}()

	if err := c.Execute(); err != nil {
		if otelShutdown != nil {
			_ = otelShutdown(context.Background())
			otelShutdown = nil
		}

		fmt.Fprintln(os.Stderr, err)
		// nolint: gocritic // false positive
		os.Exit(1)
	}
}
