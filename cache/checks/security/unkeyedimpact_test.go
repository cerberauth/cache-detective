package security_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/security"
)

// impactServer simulates a naive single-slot shared cache in front of an
// origin that reflects X-Forwarded-Host (and friends) into render exactly
// as render would, keyed purely on path — so the unkeyed header controls
// what gets cached.
func impactServer(render func(host string) string) *httptest.Server {
	var mu sync.Mutex
	cached := map[string]string{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.RequestURI()
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Header.Get("X-Host")
		}
		if host == "" {
			host = r.Header.Get("X-Original-URL")
		}
		if host == "" {
			host = r.Header.Get("X-Rewrite-URL")
		}
		if host == "" {
			host = r.Header.Get("X-Forwarded-Server")
		}

		mu.Lock()
		defer mu.Unlock()
		if host != "" {
			cached[key] = render(host)
		}
		if body, ok := cached[key]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(render("")))
	}))
}

func TestUnkeyedImpact_GatedOffWithoutAggressive(t *testing.T) {
	srv := impactServer(func(host string) string { return "<html>" + host + "</html>" })
	defer srv.Close()

	res := runChain(t, (&checkbase.ProbeCtx{Probe: probe.New()}).WithDefaults(), srv.URL, "/", checkbase.CheckIDUnkeyedImpact, security.UnkeyedImpactCheck)
	assert.False(t, res.Skipped)
	assert.Empty(t, res.Observations)
}

func TestUnkeyedImpact_DetectsReflectedXSS(t *testing.T) {
	srv := impactServer(func(host string) string {
		return `<html><link rel="canonical" href="https://` + host + `/"></html>`
	})
	defer srv.Close()

	res := runChain(t, aggressiveCtx(20), srv.URL, "/", checkbase.CheckIDUnkeyedImpact, security.UnkeyedImpactCheck)
	require.NotEmpty(t, res.Observations)
	var found bool
	for _, o := range res.Observations {
		if o.Title == "Reflected XSS via unkeyed header" {
			found = true
			assert.Equal(t, checkbase.SeverityCritical, o.Metadata[checkbase.SeverityKey])
		}
	}
	assert.True(t, found, "observations: %+v", res.Observations)
}

func TestUnkeyedImpact_EscapedHostNotFlaggedAsXSS(t *testing.T) {
	srv := impactServer(func(host string) string {
		return `<html>` + strings.ReplaceAll(strings.ReplaceAll(host, "<", "&lt;"), ">", "&gt;") + `</html>`
	})
	defer srv.Close()

	res := runChain(t, aggressiveCtx(20), srv.URL, "/", checkbase.CheckIDUnkeyedImpact, security.UnkeyedImpactCheck)
	for _, o := range res.Observations {
		assert.NotEqual(t, "Reflected XSS via unkeyed header", o.Title)
	}
}

func TestUnkeyedImpact_DetectsDOMPoisoning(t *testing.T) {
	srv := impactServer(func(host string) string {
		return `<html><script>var cfg = {"host":"` + host + `"};</script></html>`
	})
	defer srv.Close()

	res := runChain(t, aggressiveCtx(20), srv.URL, "/", checkbase.CheckIDUnkeyedImpact, security.UnkeyedImpactCheck)
	var found bool
	for _, o := range res.Observations {
		if o.Title == "DOM-based cache poisoning via unkeyed header" {
			found = true
		}
	}
	assert.True(t, found, "observations: %+v", res.Observations)
}

func TestUnkeyedImpact_DetectsScriptHijack(t *testing.T) {
	srv := impactServer(func(host string) string {
		if host == "" {
			return `<html></html>`
		}
		return `<html><script src="https://` + host + `/widget.js"></script></html>`
	})
	defer srv.Close()

	res := runChain(t, aggressiveCtx(20), srv.URL, "/", checkbase.CheckIDUnkeyedImpact, security.UnkeyedImpactCheck)
	var found bool
	for _, o := range res.Observations {
		if o.Title == "Script import hijack via unkeyed header" {
			found = true
		}
	}
	assert.True(t, found, "observations: %+v", res.Observations)
}

func TestUnkeyedImpact_DetectsOpenRedirect(t *testing.T) {
	var mu sync.Mutex
	cached := map[string]int{}
	cachedLoc := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path
		host := r.Header.Get("X-Forwarded-Host")
		proto := r.Header.Get("X-Forwarded-Proto")
		if proto == "" {
			proto = r.Header.Get("X-Forwarded-Scheme")
		}

		mu.Lock()
		defer mu.Unlock()
		if host != "" && proto != "" {
			cached[key] = http.StatusFound
			cachedLoc[key] = proto + "://" + host + "/"
		}
		if status, ok := cached[key]; ok {
			w.Header().Set("Location", cachedLoc[key])
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := runChain(t, aggressiveCtx(20), srv.URL, "/go", checkbase.CheckIDUnkeyedImpact, security.UnkeyedImpactCheck)
	var found bool
	for _, o := range res.Observations {
		if strings.HasPrefix(o.Title, "Open redirect via unkeyed X-Forwarded-Host/") {
			found = true
			assert.Equal(t, checkbase.SeverityHigh, o.Metadata[checkbase.SeverityKey])
		}
	}
	assert.True(t, found, "observations: %+v", res.Observations)
}

// TestUnkeyedImpact_DoesNotPoisonCanonicalURL asserts every probe here
// lives on its own cache-buster-isolated URL — a plain request to the
// resource's real, canonical URL never sees an injected payload.
func TestUnkeyedImpact_DoesNotPoisonCanonicalURL(t *testing.T) {
	srv := impactServer(func(host string) string {
		return `<html><link rel="canonical" href="https://` + host + `/"></html>`
	})
	defer srv.Close()

	runChain(t, aggressiveCtx(20), srv.URL, "/", checkbase.CheckIDUnkeyedImpact, security.UnkeyedImpactCheck)

	resp, err := http.Get(srv.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	body := make([]byte, 512)
	n, _ := resp.Body.Read(body)
	assert.NotContains(t, string(body[:n]), "cd-impact")
}

func TestUnkeyedImpact_RespectsRequestBudget(t *testing.T) {
	var mu sync.Mutex
	var probes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// "cd-impact" only ever appears in this check's own payload values
		// (every impactProbe/openRedirect payload embeds it), so counting
		// it isolates this check's requests from the rest of the §5 chain's.
		for _, vs := range r.Header {
			for _, v := range vs {
				if strings.Contains(v, "cd-impact") {
					mu.Lock()
					probes++
					mu.Unlock()
				}
			}
		}
		_, _ = w.Write([]byte("static"))
	}))
	defer srv.Close()

	runChain(t, aggressiveCtx(3), srv.URL, "/", checkbase.CheckIDUnkeyedImpact, security.UnkeyedImpactCheck)

	mu.Lock()
	defer mu.Unlock()
	assert.LessOrEqual(t, probes, 3)
}
