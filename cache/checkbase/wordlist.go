package checkbase

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadWordlistFile reads a newline-delimited wordlist file — one candidate
// name per line, blank lines and "#"-prefixed comments ignored — and
// returns its entries in file order. Used to load ProbeCtx.UnkeyedInputWordlist,
// which supplements the security package's bundled unkeyed-input
// candidates (header names, cookie names, query-parameter names) with
// app-specific names the bundled wordlist doesn't cover.
func LoadWordlistFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("checkbase: reading wordlist: %w", err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("checkbase: reading wordlist: %w", err)
	}
	return out, nil
}
