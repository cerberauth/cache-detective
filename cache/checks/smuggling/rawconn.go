package smuggling

import (
	"crypto/tls"
	"net"
	"net/url"
	"strings"
	"time"
)

// dialAddr returns resourceURL's dial target (host:port), defaulting the
// port from its scheme when none is given explicitly.
func dialAddr(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == schemeHTTPS {
		return u.Host + ":443"
	}
	return u.Host + ":80"
}

// dialRaw opens a plain TCP (or, over https, TLS) connection to
// resourceURL's host — never pctx.Probe's pooled/reused client. Every probe
// in this package needs its own fresh connection: a desync's effect is
// scoped to the one connection whose framing it corrupts, so sharing a
// connection across probes would let one probe's misinterpreted leftover
// bytes feed into the next and produce a meaningless result.
func dialRaw(resourceURL string) (net.Conn, *url.URL, error) {
	u, err := url.Parse(resourceURL)
	if err != nil {
		return nil, nil, err
	}

	conn, err := net.DialTimeout("tcp", dialAddr(u), rawProbeTimeout)
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme != schemeHTTPS {
		return conn, u, nil
	}

	tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), NextProtos: []string{"http/1.1"}})
	_ = tlsConn.SetDeadline(time.Now().Add(rawProbeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, u, nil
}

// sendRawTimingProbe opens a fresh connection to resourceURL, writes
// rawRequest verbatim, and returns how long it took to read the first byte
// of a response. A read that times out or a connection that closes without
// ever answering both return rawProbeTimeout — the strongest possible
// signal that something on the other end is still waiting for more data.
func sendRawTimingProbe(resourceURL, rawRequest string) (time.Duration, error) {
	conn, _, err := dialRaw(resourceURL)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	start := time.Now()
	if _, err := conn.Write([]byte(rawRequest)); err != nil {
		return 0, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(rawProbeTimeout))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	elapsed := time.Since(start)
	if err != nil {
		return rawProbeTimeout, nil
	}
	return elapsed, nil
}

// buildRawRequest assembles a raw HTTP/1.1 request: a POST request line
// against u's path (defaulting to "/"), a Host header, extraHeaders
// verbatim (in the order given — some probes rely on that order), and body
// written exactly as given rather than through any header-normalizing
// client, since the whole point of every probe here is to send a header
// combination net/http itself would refuse to construct.
func buildRawRequest(u *url.URL, extraHeaders []string, body string) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	var b strings.Builder
	b.WriteString("POST " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + u.Host + "\r\n")
	for _, h := range extraHeaders {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}
