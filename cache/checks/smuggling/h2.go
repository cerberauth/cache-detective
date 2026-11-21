package smuggling

import (
	"crypto/tls"
	"net"
	"net/url"
	"time"

	"github.com/cerberauth/harnessx"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// probeHTTP2Downgrade is a precondition advisory, not a confirmed exploit:
// crafting a genuinely malformed HTTP/2 frame to smuggle past a downgrading
// front-end needs a raw frame-level HTTP/2 client (RFC 9113's own §8.2.2
// already forbids a compliant server from honoring Content-Length/
// Transfer-Encoding games over H2 itself, so the exposure is specifically
// in how a front-end *translates* H2 to H1 for the backend — a mechanism
// this package's raw HTTP/1.1 socket approach can't reach). What's left,
// and worth flagging, is the precondition every H2-downgrade variant
// shares: the target negotiates HTTP/2 at all, over a connection that (per
// the architecture, not confirmed here) terminates and re-encodes to
// HTTP/1.1 for its origin (Kettle, "HTTP/2: The Sequel is Always Worse";
// "Browser-Powered Desync Attacks", 2022).
func probeHTTP2Downgrade(resource harnessx.Resource) (harnessx.Observation, bool) {
	u, err := url.Parse(resource.URL)
	if err != nil || u.Scheme != schemeHTTPS {
		// H2 is only ever negotiated over TLS in practice (h2c — cleartext
		// HTTP/2 — is rare enough on the public internet, and ALPN gives no
		// signal for it anyway); nothing to check for a plain http:// URL.
		return harnessx.Observation{}, false
	}

	conn, err := net.DialTimeout("tcp", dialAddr(u), rawProbeTimeout)
	if err != nil {
		return harnessx.Observation{}, false
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), NextProtos: []string{"h2", "http/1.1"}})
	_ = tlsConn.SetDeadline(time.Now().Add(rawProbeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return harnessx.Observation{}, false
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		return harnessx.Observation{}, false
	}

	return harnessx.Observation{
		CheckID:     checkbase.CheckIDSmuggling,
		ResourceID:  resource.ID,
		Title:       "HTTP/2-downgrade desync precondition",
		Description: "the target negotiates HTTP/2 over TLS. If a fronting server terminates H2 here and re-encodes to HTTP/1.1 toward its origin (common for CDNs/load balancers), it is a candidate for H2-downgrade request smuggling — a pseudo-header or header-injection payload that survives the H2-to-H1 translation into a second, attacker-controlled request line. Confirming this needs a raw HTTP/2 frame-level client this scanner doesn't carry; treat this as a lead for manual testing, not a confirmed finding",
		Evidence:    "ALPN negotiated: h2",
		Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityInfo},
	}, true
}
