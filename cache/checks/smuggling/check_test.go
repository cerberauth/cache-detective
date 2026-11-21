package smuggling_test

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/smuggling"
)

// withShortProbeTimeout temporarily shrinks smuggling's raw-probe timeout so
// a test proving a hang is detected doesn't have to wait out the real
// production window.
func withShortProbeTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	original := smuggling.SetProbeTimeoutForTest(d)
	t.Cleanup(func() { smuggling.SetProbeTimeoutForTest(original) })
}

func newEngine(t *testing.T) *harnessx.Engine {
	t.Helper()
	engine := harnessx.New()
	require.NoError(t, engine.Register(checkbase.DiscoveryCheck, smuggling.Check))
	return engine
}

func runSmuggling(t *testing.T, pctx checkbase.ProbeCtx, srvURL string) harnessx.Result {
	t.Helper()
	pctx.Resources = []checkbase.ResourceSpec{{ID: "root", URL: srvURL}}
	pctx = pctx.WithDefaults()
	summary, err := newEngine(t).Run(context.Background(), harnessx.Target{URL: srvURL, Data: &pctx})
	require.NoError(t, err)
	for _, r := range summary.Results {
		if r.CheckID == checkbase.CheckIDSmuggling && r.ResourceID == "root" {
			return r
		}
	}
	t.Fatal("no result for cache.smuggling_desync/root")
	return harnessx.Result{}
}

func aggressiveCtx(t *testing.T) checkbase.ProbeCtx {
	t.Helper()
	return checkbase.ProbeCtx{Probe: probe.New(), Aggressive: true, EnableSmuggling: true, MaxAggressiveRequests: 10}
}

// desyncServer is a bare net.Listener (not httptest/net.http, which would
// normalize or reject an ambiguous Content-Length/Transfer-Encoding
// combination before this package's raw request ever got a chance to probe
// anything) simulating a single front-end+back-end tier that recognizes
// Transfer-Encoding over Content-Length. A plain GET always answers
// immediately (the baseline measurement). A POST whose raw header block
// carries both a Content-Length and *some* spelling of Transfer-Encoding
// is treated as "chunked" when vulnerable — reading only up to the
// zero-length chunk terminator and then, simulating the backend left
// waiting on a nonexistent next request line, never answering at all —
// and as a plain Content-Length-framed request when not, answering
// immediately either way.
func desyncServer(t *testing.T, vulnerable bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleDesyncConn(conn, vulnerable)
		}
	}()
	return "http://" + ln.Addr().String() + "/"
}

func handleDesyncConn(conn net.Conn, vulnerable bool) {
	defer conn.Close()
	r := bufio.NewReader(conn)

	var method string
	var header strings.Builder
	for i := 0; ; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if i == 0 {
			method = strings.Fields(line)[0]
		}
		header.WriteString(line)
		if strings.TrimRight(line, "\r\n") == "" {
			break
		}
	}

	ambiguous := strings.Contains(header.String(), "Transfer-Encoding") && strings.Contains(header.String(), "Content-Length")
	if method == http.MethodPost && ambiguous && vulnerable {
		// Simulate the back-end left waiting on a request line that will
		// never arrive: never respond at all. The client enforces its own
		// read deadline (rawProbeTimeout), so this goroutine's connection is
		// simply abandoned when the test ends — nothing to clean up here.
		return
	}
	_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
}

func TestSmugglingCheck_GatedOffWithoutBoth(t *testing.T) {
	srv := desyncServer(t, true)

	cases := []checkbase.ProbeCtx{
		{Probe: probe.New()},
		{Probe: probe.New(), Aggressive: true},
		{Probe: probe.New(), EnableSmuggling: true},
	}
	for _, pctx := range cases {
		res := runSmuggling(t, pctx, srv)
		assert.False(t, res.Skipped)
		assert.Empty(t, res.Observations)
	}
}

func TestSmugglingCheck_DetectsCLTETiming(t *testing.T) {
	withShortProbeTimeout(t, 500*time.Millisecond)
	srv := desyncServer(t, true)

	res := runSmuggling(t, aggressiveCtx(t), srv)
	require.NotEmpty(t, res.Observations)
	assert.Contains(t, res.Observations[0].Title, "Possible request smuggling")
	assert.Equal(t, checkbase.SeverityHigh, res.Observations[0].Metadata[checkbase.SeverityKey])
}

func TestSmugglingCheck_HonestServerNotFlagged(t *testing.T) {
	withShortProbeTimeout(t, 500*time.Millisecond)
	srv := desyncServer(t, false)

	res := runSmuggling(t, aggressiveCtx(t), srv)
	for _, o := range res.Observations {
		assert.NotContains(t, o.Title, "Possible request smuggling")
	}
}

func TestSmugglingCheck_RespectsRequestBudget(t *testing.T) {
	withShortProbeTimeout(t, 200*time.Millisecond)
	var connCount int
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connCount++
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
			}(conn)
		}
	}()
	srv := "http://" + ln.Addr().String() + "/"

	pctx := aggressiveCtx(t)
	pctx.MaxAggressiveRequests = 3
	runSmuggling(t, pctx, srv)
	_ = ln.Close()
	<-done

	// 1 baseline (GET, via the normal client, not a raw connection counted
	// here) — actually counted too, since it's the same listener — plus up
	// to budget-1 raw timing probes, plus the CSD precondition's own extra
	// GET when the baseline isn't a redirect (it isn't here, so CSD never
	// opens a second connection). Generous upper bound: budget (3) timing
	// probes plus the baseline GET plus the H2-downgrade precondition
	// (skipped for a plain http:// URL) — never more than budget+1.
	assert.LessOrEqual(t, connCount, 4)
}
