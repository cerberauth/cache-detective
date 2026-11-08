package crawl

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// harFile mirrors the subset of the HAR 1.2 schema this package reads:
// each entry's request method, URL, headers and cookies.
type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method  string    `json:"method"`
				URL     string    `json:"url"`
				Headers []harPair `json:"headers"`
				Cookies []harPair `json:"cookies"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

type harPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HAROptions configures FromHAR.
type HAROptions struct {
	// ReplayRequestHeaders attaches each entry's recorded request headers
	// and cookies to its ResourceSpec so the scan replays them. Off by
	// default: a HAR typically holds live session tokens, so replaying
	// them (and treating the scan as authenticated) must be an explicit
	// choice.
	ReplayRequestHeaders bool
}

// notReplayed are recorded request headers that are never replayed:
// connection-level or transport-managed (Host, Content-Length, Accept-Encoding —
// setting the latter disables transparent decompression), identification the
// probe sets itself (User-Agent), and cache-validation / cache-bypass headers a
// browser adds on reload or revalidation that would skew every cache check
// (If-*, Range, Cache-Control, Pragma). Cookies are handled separately.
var notReplayed = map[string]bool{
	"Host": true, "Content-Length": true, "Content-Type": true, "Connection": true,
	"Keep-Alive": true, "Transfer-Encoding": true, "Upgrade": true, "Te": true,
	"Accept-Encoding": true, "User-Agent": true, "Cookie": true, "Range": true,
	"If-Range": true, "If-Match": true, "If-None-Match": true,
	"If-Modified-Since": true, "If-Unmodified-Since": true,
	"Cache-Control": true, "Pragma": true, "Expect": true,
}

// FromHAR reads a .har file and returns one ResourceSpec per distinct
// GET/HEAD (method, URL) pair, replaying each with the method the browser used
// (HAR captures every request a browser made, including non-idempotent
// ones cache-detective has no business replaying). With
// opts.ReplayRequestHeaders, the first recorded entry for each pair also
// supplies the headers and cookies to send.
func FromHAR(path string, opts HAROptions) ([]checkbase.ResourceSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crawl: reading .har file: %w", err)
	}
	var har harFile
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("crawl: parsing .har file: %w", err)
	}

	type key struct{ method, url string }
	seen := map[key]bool{}
	var specs []checkbase.ResourceSpec
	for _, e := range har.Log.Entries {
		method := strings.ToUpper(e.Request.Method)
		switch method {
		case "GET", "HEAD":
		case "":
			method = "GET"
		default:
			continue
		}
		k := key{method, e.Request.URL}
		if e.Request.URL == "" || seen[k] {
			continue
		}
		seen[k] = true
		spec := checkbase.ResourceSpec{URL: e.Request.URL, Method: method}
		if opts.ReplayRequestHeaders {
			spec.Headers, spec.Cookies = replayable(e.Request.Headers, e.Request.Cookies)
		}
		specs = append(specs, spec)
	}

	// ID resources by path (like FromURLs), disambiguating collisions.
	ids := map[string]int{}
	for i := range specs {
		id := resourceID(specs[i].URL)
		if n := ids[id]; n > 0 {
			id = fmt.Sprintf("%s#%d", id, n+1)
		}
		ids[resourceID(specs[i].URL)]++
		specs[i].ID = id
	}
	return specs, nil
}

// replayable filters a recorded request's headers down to the ones worth
// replaying and returns its cookies (from the Cookie header, falling back
// to the HAR cookies array).
func replayable(headers, cookies []harPair) (map[string][]string, []checkbase.Cookie) {
	var out map[string][]string
	raw := http.Header{}
	for _, h := range headers {
		// HTTP/2 pseudo-headers (":authority", ...) are not real headers.
		if h.Name == "" || strings.HasPrefix(h.Name, ":") {
			continue
		}
		name := http.CanonicalHeaderKey(h.Name)
		raw.Add(name, h.Value)
		if notReplayed[name] {
			continue
		}
		if out == nil {
			out = map[string][]string{}
		}
		out[name] = append(out[name], h.Value)
	}

	var cs []checkbase.Cookie
	for _, c := range (&http.Request{Header: raw}).Cookies() {
		cs = append(cs, checkbase.Cookie{Name: c.Name, Value: c.Value})
	}
	if len(cs) == 0 {
		for _, c := range cookies {
			if c.Name != "" {
				cs = append(cs, checkbase.Cookie{Name: c.Name, Value: c.Value})
			}
		}
	}
	return out, cs
}
