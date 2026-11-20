package security

import "time"

// SetCPDoSTTLWindowForTest overrides cpdosTTLWindow for the duration of a
// test, returning a restore func. Exported here (not in the package's real
// API) purely so security_test can exercise the CPDoS probes'
// delayed re-check without spending cpdosTTLWindow's real-world delay on
// every test run.
func SetCPDoSTTLWindowForTest(d time.Duration) func() {
	prev := cpdosTTLWindow
	cpdosTTLWindow = d
	return func() { cpdosTTLWindow = prev }
}
