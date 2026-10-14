package security

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// --- Web cache entanglement: fat GET & parameter cloaking (§5) -------------

var EntanglementDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDEntanglement),
	Name:        "Web Cache Entanglement (Fat GET & Parameter Cloaking)",
	Description: "Looks for request inputs the origin parses but the cache key ignores: a GET request body that overrides the query string (\"fat GET\"), and a query parameter hidden behind a \";\" the cache stops reading at but the origin treats as a parameter separator (\"parameter cloaking\"). Each is confirmed the Param Miner way — a marker injected via the input must be served back to a follow-up plain request (Kettle, \"Web Cache Entanglement: Novel Pathways to Poisoning\", Black Hat USA 2020).",
	Tags:        []string{securityTag, cachePoisoningTag, cacheKeyTag, "fat-get", "parameter-cloaking"},
	// DependsOn CPDoSCheck, the tail of the §5 poison chain, and joins at the
	// same level as varykey/delimiter-mapper. Unlike the chain's older
	// members this check never touches the resource's canonical entry: every
	// poison/confirm pair lives on its own cache-buster-isolated URL.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDCPDoS)},
	CVSSVector: cvssPoisoning,
	CVSSScore:  9.3,
	CWEID:      "CWE-436",
	OWASP:      owaspMisconfig,
}

var EntanglementCheck = checkdef.NewResourceCheck(EntanglementDef, runEntanglement)

// cloakedParamWordlist are parameter names tried behind a ";" in addition to
// the resource's own query parameters. Ordered by how often an application
// reflects them; "name" and "q" come first since a reflected greeting/search
// term is the textbook parameter-cloaking target.
var cloakedParamWordlist = []string{
	"name",
	"q",
	"search",
	"query",
	"callback",
	"redirect",
	"url",
	langParam,
}

func runEntanglement(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)
	budget := pctx.MaxAggressiveRequests

	var obs []harnessx.Observation
	// A body on a non-GET method is just a normal request body, not a
	// discrepancy, so fat GET only applies to GET resources.
	if pctx.Method == "" || strings.EqualFold(pctx.Method, http.MethodGet) {
		obs = append(obs, probeFatGET(ctx, pctx, resource, &budget)...)
	}
	obs = append(obs, probeParameterCloaking(ctx, pctx, resource, &budget)...)

	return harnessx.Result{Observations: obs}, nil
}

// fatBody is one GET request body shape tried by probeFatGET.
type fatBody struct {
	contentType string
	content     string
}

// fatGETBodies returns the body shapes to try: the raw marker (frameworks
// that read the body as the value), then form-encoded and JSON bodies keyed
// by the resource's own parameter names (frameworks that merge body
// parameters over query parameters).
func fatGETBodies(resourceURL string) []fatBody {
	names := queryParamNames(resourceURL)
	if len(names) == 0 {
		names = []string{"q"}
	}
	if len(names) > 2 {
		names = names[:2]
	}

	bodies := []fatBody{{contentType: "text/plain", content: unkeyedInputMarker}}
	for _, n := range names {
		bodies = append(bodies, fatBody{contentType: "application/x-www-form-urlencoded", content: url.QueryEscape(n) + "=" + unkeyedInputMarker})
	}
	bodies = append(bodies, fatBody{contentType: "application/json", content: fmt.Sprintf("{%q:%q}", names[0], unkeyedInputMarker)})
	return bodies
}

// probeFatGET sends a GET carrying a marker in its body to a
// cache-buster-isolated URL. If the marker is reflected, a body-less follow-up
// to the same URL is the confirmation: serving the marker back means the
// origin let the body shape the response while the cache keyed on the URL
// alone.
func probeFatGET(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, budget *int) []harnessx.Observation {
	for _, fb := range fatGETBodies(resource.URL) {
		if *budget < 1 {
			return nil
		}
		busterProbe, err := checkbase.NewCacheBusterProbe(resource.URL, pctx)
		if err != nil {
			continue
		}
		poisonReq, err := checkbase.NewRequest(ctx, busterProbe.URL, pctx, busterProbe.Header)
		if err != nil {
			continue
		}
		setRequestBody(poisonReq, fb.contentType, fb.content)

		*budget--
		poisoned, err := checkbase.Do(ctx, pctx, poisonReq)
		if err != nil || !reflectsMarker(poisoned) {
			continue
		}

		if *budget < 1 {
			return nil
		}
		*budget--
		confirm, err := fetchExchangeWithHeader(ctx, pctx, busterProbe.URL, busterProbe.Header)
		if err != nil || !reflectsMarker(confirm) {
			continue
		}
		return []harnessx.Observation{{
			CheckID:     checkbase.CheckIDEntanglement,
			ResourceID:  resource.ID,
			Title:       "Cache poisoning via fat GET request body",
			Description: fmt.Sprintf("a marker sent in the body of a GET request (%s) was reflected into the response and then served, unmodified, to a follow-up body-less GET of the same URL — the origin reads the GET body but the cache keys on the URL alone, so a body-controlled payload poisons the entry for every caller", fb.contentType),
			Evidence:    fmt.Sprintf("GET body (%s): %s", fb.contentType, fb.content),
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityCritical},
		}}
	}
	return nil
}

// probeParameterCloaking appends ";<name>=<marker>" to a cache-buster-isolated
// URL's query for each candidate parameter name. A cache that stops reading
// the query at the first ";" keys the request exactly like the plain URL,
// while an origin that treats ";" as a parameter separator (Rails, older
// Java/Tomcat setups) still reads the cloaked parameter. As elsewhere, the
// confirmation is a plain follow-up request being served the marker.
func probeParameterCloaking(ctx context.Context, pctx *checkbase.ProbeCtx, resource harnessx.Resource, budget *int) []harnessx.Observation {
	candidates := dedupeCandidates(append(queryParamNames(resource.URL), cloakedParamWordlist...), pctx.UnkeyedInputWordlist)

	for _, name := range candidates {
		if *budget < 1 {
			return nil
		}
		busterProbe, err := checkbase.NewCacheBusterProbe(resource.URL, pctx)
		if err != nil {
			continue
		}
		cloaked := appendCloakedParam(busterProbe.URL, name, unkeyedInputMarker)
		poisonReq, err := checkbase.NewRequest(ctx, cloaked, pctx, busterProbe.Header)
		if err != nil {
			continue
		}

		*budget--
		poisoned, err := checkbase.Do(ctx, pctx, poisonReq)
		if err != nil || !reflectsMarker(poisoned) {
			continue
		}

		if *budget < 1 {
			return nil
		}
		*budget--
		confirm, err := fetchExchangeWithHeader(ctx, pctx, busterProbe.URL, busterProbe.Header)
		if err != nil || !reflectsMarker(confirm) {
			continue
		}
		return []harnessx.Observation{{
			CheckID:     checkbase.CheckIDEntanglement,
			ResourceID:  resource.ID,
			Title:       fmt.Sprintf("Cache poisoning via parameter cloaking (%s)", name),
			Description: fmt.Sprintf("a marker placed in %q behind a \";\" was reflected into the response and then served, unmodified, to a follow-up request without it — the origin parses \";\" as a parameter separator while the cache keys on the query only up to the \";\", so an attacker can cloak a payload from the cache key", name),
			Evidence:    "probed: " + cloaked,
			Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityCritical},
		}}
	}
	return nil
}

// appendCloakedParam appends ";name=value" to rawURL's raw query string,
// verbatim — url.Values.Encode would percent-encode the ";" and defeat the
// probe. A URL with no query gets a leading "?" so the cloaked parameter is
// still in the query rather than the path.
func appendCloakedParam(rawURL, name, value string) string {
	sep := ";"
	if !strings.Contains(rawURL, "?") {
		sep = "?;"
	}
	return rawURL + sep + url.QueryEscape(name) + "=" + value
}

// setRequestBody attaches content to req as its body. GetBody is set too, so
// a retrying probe client can replay it.
func setRequestBody(req *http.Request, contentType, content string) {
	req.Body = io.NopCloser(strings.NewReader(content))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(content)), nil }
	req.ContentLength = int64(len(content))
	req.Header.Set("Content-Type", contentType)
}

// reflectsMarker reports whether ex carries unkeyedInputMarker in its body or
// any response header.
func reflectsMarker(ex checkbase.Exchange) bool {
	return strings.Contains(string(ex.Body), unkeyedInputMarker) || containsHeaderValue(ex.Header, unkeyedInputMarker)
}

// queryParamNames returns rawURL's query parameter names, sorted so probe
// order is deterministic.
func queryParamNames(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	q := u.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// fetchExchangeWithHeader is fetchExchange with extra request headers (a
// cache-buster header, in CacheBusterHeader/Both mode).
func fetchExchangeWithHeader(ctx context.Context, pctx *checkbase.ProbeCtx, rawURL string, extra http.Header) (checkbase.Exchange, error) {
	req, err := checkbase.NewRequest(ctx, rawURL, pctx, extra)
	if err != nil {
		return checkbase.Exchange{}, err
	}
	return checkbase.Do(ctx, pctx, req)
}
