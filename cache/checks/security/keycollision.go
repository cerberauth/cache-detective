package security

import (
	"context"
	"fmt"
	"net/url"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

// --- Cache-key path collision (§5) -----------------------------------------

var KeyCollisionDef = checkbase.CheckDef{
	ID:          string(checkbase.CheckIDKeyCollision),
	Name:        "Cache-Key Path Collision",
	Description: "Detects a cache that normalizes \"../\" segments before computing its cache key while the origin routes the raw path: a request for /static/x/../../victim is served by the origin as static content, but stored under the key /victim — so one request can overwrite any other path's cache entry (\"cache what/where\", Doyhenard, \"Gotta cache 'em all\", Black Hat USA 2024). Probed against a random, never-used path so no real entry is ever overwritten.",
	Tags:        []string{securityTag, cachePoisoningTag, cacheKeyTag},
	// Same ordering rationale as EntanglementDef. Probing a random path also
	// means this check can't be disturbed by (or disturb) the other checks'
	// traffic to the resource itself.
	DependsOn:  []string{string(checkbase.CheckIDDiscovery), string(checkbase.CheckIDCPDoS)},
	CVSSVector: cvssPoisoning,
	CVSSScore:  9.3,
	CWEID:      "CWE-436",
	OWASP:      owaspMisconfig,
}

var KeyCollisionCheck = checkdef.NewResourceCheck(KeyCollisionDef, runKeyCollision)

// collisionVariants are the traversal spellings tried between the static
// directory and the collided-onto path: plain, and with the separator
// percent-encoded (some caches decode before normalizing, some after).
var collisionVariants = []struct {
	name string
	up   string
}{
	{name: "plain", up: "/../../"},
	{name: "encoded", up: "/..%2f..%2f"},
}

func runKeyCollision(ctx context.Context, target harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	if !aggressiveGate(target) {
		return harnessx.Result{}, nil
	}
	pctx := target.Data.(*checkbase.ProbeCtx)
	budget := pctx.MaxAggressiveRequests
	if budget < 3 {
		return harnessx.Result{}, nil
	}

	u, err := url.Parse(resource.URL)
	if err != nil {
		return harnessx.Result{}, err
	}
	origin := u.Scheme + "://" + u.Host

	// What a nonexistent path looks like on this origin. A poisoned response
	// only counts if it differs from this: on a catch-all origin every path
	// answers alike and nothing can be told apart.
	budget--
	missing, err := fetchExchange(ctx, pctx, origin+"/"+randomPathToken())
	if err != nil {
		return harnessx.Result{}, nil
	}

	seg := randomPathToken()
	for _, prefix := range staticDirPrefixes {
		for _, v := range collisionVariants {
			if budget < 2 {
				return harnessx.Result{}, nil
			}
			budget -= 2

			// The path being collided onto: random, never requested by anyone,
			// so overwriting its cache entry harms nothing. If the cache keys
			// the poison request as /<victim>, a plain request for it is the
			// only thing that can come back with the poison response.
			victim := randomPathToken()
			poisonPath := prefix + "/" + seg + v.up + victim
			poisonURL := origin + poisonPath
			poisoned, err := fetchExchange(ctx, pctx, poisonURL)
			if err != nil || poisoned.StatusCode/100 != 2 || sameResponse(missing, poisoned) {
				// Not served as distinct content: the origin normalizes too (or
				// has no such static route), so there is no discrepancy here.
				continue
			}

			confirm, err := fetchExchange(ctx, pctx, origin+"/"+victim)
			if err != nil || !sameResponse(poisoned, confirm) {
				continue
			}
			return harnessx.Result{Observations: []harnessx.Observation{{
				CheckID:     checkbase.CheckIDKeyCollision,
				ResourceID:  resource.ID,
				Title:       "Cache-key path collision via path traversal",
				Description: fmt.Sprintf("a request for %q was answered by the origin with static content, and a later plain request for the unrelated path /%s was served that same content — the cache normalized the traversal before keying while the origin routed the raw path, so a single request can plant attacker-influenced content under any path's cache key, including a high-value one such as an account page", poisonPath, victim),
				Evidence:    "probed: " + poisonURL,
				Metadata:    map[string]string{checkbase.SeverityKey: checkbase.SeverityCritical},
			}}}, nil
		}
	}
	return harnessx.Result{}, nil
}
