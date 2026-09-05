package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
)

// diffFinding mirrors reportx's on-disk JSON finding shape (see
// reportx/format/json.go) — just enough fields to key and describe a
// finding for drift comparison.
type diffFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	URL         string `json:"url"`
	Parameter   string `json:"parameter"`
	Description string `json:"description"`
}

type diffReport struct {
	Metadata struct {
		Target   string `json:"target"`
		ScanDate string `json:"scan_date"`
	} `json:"metadata"`
	Findings []diffFinding `json:"findings"`
}

func (f diffFinding) key() string {
	if f.ID != "" {
		return f.ID + "|" + f.URL + "|" + f.Parameter
	}
	return f.Title + "|" + f.URL + "|" + f.Parameter
}

var diffCmd = &cobra.Command{
	Use:   "diff <before.json> <after.json>",
	Short: "Compare two cache-detective JSON scans to detect cache-config drift",
	Long: `Compares two scans (each produced via "cache-detective scan --output-format json --output <file>")
over time, reporting findings that newly appeared, disappeared, or changed
severity between the two — cache-config drift detection (§9).`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		before, err := loadDiffReport(args[0])
		if err != nil {
			return err
		}
		after, err := loadDiffReport(args[1])
		if err != nil {
			return err
		}

		beforeByKey := indexFindings(before.Findings)
		afterByKey := indexFindings(after.Findings)

		var added, removed, changed []string
		for k, f := range afterByKey {
			b, existed := beforeByKey[k]
			switch {
			case !existed:
				added = append(added, fmt.Sprintf("+ [%s] %s (%s)", f.Severity, f.Title, f.URL))
			case b.Severity != f.Severity:
				changed = append(changed, fmt.Sprintf("~ [%s -> %s] %s (%s)", b.Severity, f.Severity, f.Title, f.URL))
			}
		}
		for k, f := range beforeByKey {
			if _, existed := afterByKey[k]; !existed {
				removed = append(removed, fmt.Sprintf("- [%s] %s (%s)", f.Severity, f.Title, f.URL))
			}
		}

		sort.Strings(added)
		sort.Strings(removed)
		sort.Strings(changed)

		fmt.Fprintf(cmd.OutOrStdout(), "Target: %s -> %s\n\n", before.Metadata.Target, after.Metadata.Target)
		printSection(cmd, "Added", added)
		printSection(cmd, "Removed", removed)
		printSection(cmd, "Changed severity", changed)

		if len(added) > 0 || len(changed) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func printSection(cmd *cobra.Command, title string, lines []string) {
	fmt.Fprintf(cmd.OutOrStdout(), "%s (%d):\n", title, len(lines))
	for _, l := range lines {
		fmt.Fprintln(cmd.OutOrStdout(), "  "+l)
	}
	fmt.Fprintln(cmd.OutOrStdout())
}

func indexFindings(findings []diffFinding) map[string]diffFinding {
	out := make(map[string]diffFinding, len(findings))
	for _, f := range findings {
		out[f.key()] = f
	}
	return out
}

func loadDiffReport(path string) (diffReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return diffReport{}, fmt.Errorf("diff: reading %s: %w", path, err)
	}
	var r diffReport
	if err := json.Unmarshal(data, &r); err != nil {
		return diffReport{}, fmt.Errorf("diff: parsing %s: %w", path, err)
	}
	return r, nil
}
