package smuggling

import (
	"bufio"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cerberauth/harnessx"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// probeClientSideDesync checks the one precondition for client-side desync
// (CSD) that's observable from the server side alone: a kept-alive
// connection whose response carries more bytes on the wire than its own
// declared Content-Length. CSD itself (Kettle, "Browser-Powered Desync
// Attacks", 2022) is the victim's *browser* reusing that same connection
// for its next same-origin request and prepending the server's leftover
// bytes onto it — not something a server-side scanner can trigger or
// confirm by itself, hence "precondition", not a confirmed finding.
//
// Only a 3xx redirect is probed: it's the shape Kettle's research found
// this in practice (an app framework that sends a short HTML body "in case
// the client doesn't follow the redirect" but miscounts it), and probing
// every response would cost a full extra read per resource for no added
// signal — a redirect is already the resource most likely to carry an
// afterthought body. baseline is run's own measureBaseline result, reused
// here so this probe doesn't issue a second, redundant plain request just
// to learn the status code checkbase.Do already told the caller.
func probeClientSideDesync(resource harnessx.Resource, baseline checkbase.Exchange) (harnessx.Observation, bool) {
	u, err := url.Parse(resource.URL)
	if err != nil {
		return harnessx.Observation{}, false
	}
	if baseline.StatusCode < 300 || baseline.StatusCode >= 400 {
		// Only worth the extra raw round-trip against a resource that's
		// actually a redirect.
		return harnessx.Observation{}, false
	}

	conn, _, err := dialRaw(resource.URL)
	if err != nil {
		return harnessx.Observation{}, false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(rawProbeTimeout))
	if _, err := conn.Write([]byte(buildPlainGetRequest(u))); err != nil {
		return harnessx.Observation{}, false
	}

	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return harnessx.Observation{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return harnessx.Observation{}, false
	}
	if strings.EqualFold(resp.Header.Get("Connection"), "close") {
		// Drained on a connection the server itself is about to close — no
		// bytes can carry over to a reused connection, so no precondition.
		return harnessx.Observation{}, false
	}
	declared, err := strconv.Atoi(resp.Header.Get("Content-Length"))
	if err != nil {
		// Chunked or no declared length at all: this check only targets the
		// specific "declared length disagrees with actual bytes sent" shape.
		return harnessx.Observation{}, false
	}

	drained := 0
	buf := make([]byte, 512)
	for drained < declared {
		n, err := resp.Body.Read(buf)
		drained += n
		if err != nil {
			break
		}
	}

	// Anything still buffered in r past the declared Content-Length arrived
	// on the wire *as part of this same response* — bytes the server sent
	// but didn't account for, left sitting on a connection it intends to
	// keep open.
	if r.Buffered() == 0 {
		return harnessx.Observation{}, false
	}

	return harnessx.Observation{
		CheckID:     checkbase.CheckIDSmuggling,
		ResourceID:  resource.ID,
		Title:       "Client-side desync (CSD) precondition",
		Description: "a kept-alive redirect response carried more bytes on the wire than its own declared Content-Length — the server-side precondition for client-side desync: a browser that reuses this connection for its next same-origin request would prepend the server's own leftover bytes onto that request, letting an attacker who controls what lands in the leftover (e.g. a reflected value in this response) smuggle arbitrary content into a victim's own subsequent request (Kettle, \"Browser-Powered Desync Attacks\", 2022). Not a confirmed exploit — a real CSD attack needs a victim's browser to reuse the connection, which this scanner can't simulate",
		Evidence:    "redirect response carried extra undeclared bytes past its Content-Length on a kept-alive connection",
		Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityInfo},
	}, true
}

// buildPlainGetRequest is a minimal, well-formed GET — no probe payload, no
// deliberate ambiguity — used only to read the raw bytes of an otherwise
// ordinary response.
func buildPlainGetRequest(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return "GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nConnection: keep-alive\r\n\r\n"
}
