package crawl

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// harFile mirrors the subset of the HAR 1.2 schema this package reads:
// each entry's request method and URL.
type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method string `json:"method"`
				URL    string `json:"url"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

// FromHAR reads a .har file and returns one ResourceSpec per GET/HEAD entry
// (HAR captures every request a browser made, including non-idempotent
// ones cache-detective has no business replaying).
func FromHAR(path string) ([]checkbase.ResourceSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crawl: reading .har file: %w", err)
	}
	var har harFile
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("crawl: parsing .har file: %w", err)
	}

	seen := map[string]bool{}
	var urls []string
	for _, e := range har.Log.Entries {
		switch e.Request.Method {
		case "GET", "HEAD", "":
		default:
			continue
		}
		if e.Request.URL == "" || seen[e.Request.URL] {
			continue
		}
		seen[e.Request.URL] = true
		urls = append(urls, e.Request.URL)
	}
	return FromURLs(urls), nil
}
