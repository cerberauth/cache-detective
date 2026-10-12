package checkbase_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/cache-detective/cache/checkbase"
)

func TestLoadWordlistFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wordlist.txt")
	require.NoError(t, os.WriteFile(path, []byte("X-Custom-Header\n# a comment\n\nX-Another-Header\n"), 0o600))

	got, err := checkbase.LoadWordlistFile(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"X-Custom-Header", "X-Another-Header"}, got)
}

func TestLoadWordlistFile_MissingFile(t *testing.T) {
	_, err := checkbase.LoadWordlistFile(filepath.Join(t.TempDir(), "missing.txt"))
	assert.Error(t, err)
}
