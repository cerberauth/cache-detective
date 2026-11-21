package smuggling

import "time"

// SetProbeTimeoutForTest overrides rawProbeTimeout for the duration of a
// test and returns the previous value, so a test proving a hang is detected
// doesn't have to wait out the real production window. Exported only to
// _test.go files via Go's package-internal export_test.go convention.
func SetProbeTimeoutForTest(d time.Duration) time.Duration {
	old := rawProbeTimeout
	rawProbeTimeout = d
	return old
}
