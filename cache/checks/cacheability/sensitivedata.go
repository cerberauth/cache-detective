package cacheability

import "regexp"

// sensitiveDataPatterns are cheap, no-dependency heuristics for content that
// makes an authenticated-but-cacheable response (AuthDef) more than a
// theoretical misconfiguration: if a shared cache actually serves this body
// to another user, these are the kinds of values that leak. Not exhaustive —
// a false negative here just leaves the finding at its base severity, it
// never suppresses it.
var sensitiveDataPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"email address", regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`)},
	{"credential/token field", regexp.MustCompile(`(?i)"(access_token|refresh_token|api_key|apikey|secret|password|ssn|credit_card|card_number)"\s*:\s*"[^"]+"`)},
	{"credit card number", regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`)},
	{"SSN", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
}

// DetectSensitiveData scans a response body and Set-Cookie headers for
// content whose presence in a shared cache is a concrete rather than
// theoretical leak, per issue's escalation criteria: PII, tokens, or
// Set-Cookie. Returns the matched reasons (empty when nothing was found).
func DetectSensitiveData(body []byte, setCookie []string) []string {
	var reasons []string
	if len(setCookie) > 0 {
		reasons = append(reasons, "Set-Cookie header present")
	}
	for _, p := range sensitiveDataPatterns {
		if p.pattern.Match(body) {
			reasons = append(reasons, p.name+" found in response body")
		}
	}
	return reasons
}
