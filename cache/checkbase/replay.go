package checkbase

import (
	"net/url"
	"sort"
	"strings"
)

// replayIndex finds the recorded request headers/cookies (ResourceSpec.Headers
// and .Cookies) that apply to a request URL. Checks rarely request a
// resource's exact URL — they add cache-busters or append path-confusion
// suffixes — so lookup tolerates that: exact URL first, then the same
// origin and path, then the longest same-origin resource path that is a
// path-segment prefix of the request's path.
type replayIndex struct {
	byURL    map[string]*ResourceSpec
	byOrigin map[string][]*ResourceSpec // longest path first
}

func newReplayIndex(specs []ResourceSpec) *replayIndex {
	var idx *replayIndex
	for i := range specs {
		spec := &specs[i]
		if len(spec.Headers) == 0 && len(spec.Cookies) == 0 {
			continue
		}
		u, err := url.Parse(spec.URL)
		if err != nil {
			continue
		}
		if idx == nil {
			idx = &replayIndex{byURL: map[string]*ResourceSpec{}, byOrigin: map[string][]*ResourceSpec{}}
		}
		if _, dup := idx.byURL[spec.URL]; !dup {
			idx.byURL[spec.URL] = spec
		}
		o := requestOrigin(u)
		idx.byOrigin[o] = append(idx.byOrigin[o], spec)
	}
	if idx == nil {
		return nil
	}
	for _, list := range idx.byOrigin {
		sort.SliceStable(list, func(i, j int) bool { return pathOf(list[i].URL) > pathOf(list[j].URL) })
	}
	return idx
}

func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Path
}

func (idx *replayIndex) lookup(u *url.URL) *ResourceSpec {
	if idx == nil {
		return nil
	}
	if spec, ok := idx.byURL[u.String()]; ok {
		return spec
	}
	for _, spec := range idx.byOrigin[requestOrigin(u)] {
		p := strings.TrimSuffix(pathOf(spec.URL), "/")
		if u.Path == p || u.Path == p+"/" || strings.HasPrefix(u.Path, p+"/") || (p == "" && strings.HasPrefix(u.Path, "/")) {
			return spec
		}
	}
	return nil
}
