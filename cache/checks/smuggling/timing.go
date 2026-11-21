package smuggling

import (
	"fmt"
	"net/url"
	"time"

	"github.com/cerberauth/harnessx"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// clteBody is the body shared by the CL.TE probe and every TE.TE
// obfuscation variant: 6 bytes, "0\r\n\r\nX". A party reading it as chunked
// sees "0\r\n\r\n" — a valid zero-length final chunk — as the complete body,
// leaving the trailing "X" as the start of what it believes is a second,
// pipelined request; a party reading it by Content-Length (6) reads all of
// it as this request's body instead. Whichever party does the former and
// forwards the full 6 declared bytes to the other is left with that other
// party waiting on a request line that will never arrive.
const clteBody = "0\r\n\r\nX"

// teclBody is the CL.TE probe's mirror: a chunked-encoded body (chunk "8" /
// "SMUGGLED" / terminator) that a Transfer-Encoding reader consumes in
// full, while a Content-Length: 3 reader stops after only "8\r\n" and is
// left believing "SMUGGLED\r\n0\r\n\r\n" is the start of a second request.
const teclBody = "8\r\nSMUGGLED\r\n0\r\n\r\n"

// teObfuscations are header spellings that some HTTP implementations still
// treat as a real "Transfer-Encoding: chunked" while others reject or
// ignore — each is the same underlying CL/TE disagreement as the plain
// CL.TE probe, just reached because one tier recognizes the obfuscated form
// and the other doesn't (Kettle's "HTTP/1.1 must die", 2025, catalogs
// several still-exploitable variants of these).
var teObfuscations = []struct {
	name   string
	header string
}{
	{name: "TE.TE: invalid chunked keyword", header: "Transfer-Encoding: xchunked"},
	{name: "TE.TE: space before colon", header: "Transfer-Encoding : chunked"},
	{name: "TE.TE: duplicate header", header: "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"},
	{name: "TE.TE: tab-prefixed header", header: "\tTransfer-Encoding: chunked"},
}

// probeDesyncTiming runs the CL.TE, TE.CL, and TE.TE differential timing
// probes against resource, each on its own fresh connection, comparing
// against baseline — the plain request's own measured response time — and
// stopping at the first confirmed delay: on a genuinely desync-vulnerable
// connection, the backend is left mid-request until it idles out, so
// running further variants against the same resource would likely just
// observe that same residual hang rather than test anything new.
func probeDesyncTiming(resource harnessx.Resource, baseline time.Duration, budget *int) []harnessx.Observation {
	u, err := url.Parse(resource.URL)
	if err != nil {
		return nil
	}

	variants := []struct {
		name    string
		headers []string
		body    string
	}{
		{name: "CL.TE", headers: []string{"Content-Length: 6", "Transfer-Encoding: chunked"}, body: clteBody},
		{name: "TE.CL", headers: []string{"Content-Length: 3", "Transfer-Encoding: chunked"}, body: teclBody},
	}
	for _, obf := range teObfuscations {
		variants = append(variants, struct {
			name    string
			headers []string
			body    string
		}{name: obf.name, headers: []string{"Content-Length: 6", obf.header}, body: clteBody})
	}

	for _, v := range variants {
		if *budget < 1 {
			return nil
		}
		*budget--

		rawReq := buildRawRequest(u, v.headers, v.body)
		elapsed, err := sendRawTimingProbe(resource.URL, rawReq)
		if err != nil {
			continue
		}
		if !desyncDelayed(elapsed, baseline) {
			continue
		}

		return []harnessx.Observation{{
			CheckID:     checkbase.CheckIDSmuggling,
			ResourceID:  resource.ID,
			Title:       fmt.Sprintf("Possible request smuggling (%s timing)", v.name),
			Description: fmt.Sprintf("a %s-style request with a Content-Length/Transfer-Encoding disagreement took %s to answer (or never did), against a %s baseline — consistent with one tier reading the request body by a different rule than the other and being left waiting for a request line that never arrives. This is a timing signal, not a destructive confirmation: a WAF/rate-limiter deliberately slowing malformed requests can produce the same symptom, so treat this as a strong lead to confirm manually (Kettle, \"HTTP Desync Attacks\", 2019) before reporting it as exploitable", v.name, elapsed, baseline),
			Evidence:    fmt.Sprintf("variant=%s elapsed=%s baseline=%s", v.name, elapsed, baseline),
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityHigh},
		}}
	}
	return nil
}
