package checkbase

import (
	"encoding/json"
	"fmt"
	"os"
)

// authProfileFile is the on-disk shape of an auth-profile config: a map
// from target origin (scheme://host[:port]) to the credentials sent to it,
// e.g.:
//
//	{
//	  "https://api.example.com": {"bearer": "eyJ..."},
//	  "https://admin.example.com": {"cookies": {"session": "abc123"}}
//	}
type authProfileFile struct {
	Headers map[string][]string `json:"headers"`
	Cookies map[string]string   `json:"cookies"`
	Bearer  string              `json:"bearer"`
}

// LoadAuthProfiles reads a JSON auth-profile file from path and returns it
// as ProbeCtx.AuthProfiles, keyed by origin. This lets a single batch/crawl
// run carry different credentials for different hosts instead of one
// global Headers/Cookies/BearerToken applied to every resource.
func LoadAuthProfiles(path string) (map[string]AuthProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("checkbase: reading auth profiles: %w", err)
	}

	var raw map[string]authProfileFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("checkbase: parsing auth profiles: %w", err)
	}

	profiles := make(map[string]AuthProfile, len(raw))
	for origin, f := range raw {
		cookies := make([]Cookie, 0, len(f.Cookies))
		for name, value := range f.Cookies {
			cookies = append(cookies, Cookie{Name: name, Value: value})
		}
		profiles[origin] = AuthProfile{
			Headers:     f.Headers,
			Cookies:     cookies,
			BearerToken: f.Bearer,
		}
	}
	return profiles, nil
}
