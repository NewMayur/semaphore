package db

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/semaphoreui/semaphore/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withSecretsDir points util.Config at a throwaway secrets directory and restores
// the previous global afterwards, so tests that share this package don't leak
// configuration into each other.
func withSecretsDir(t *testing.T, dir string) {
	t.Helper()

	previous := util.Config
	t.Cleanup(func() { util.Config = previous })

	util.Config = &util.ConfigType{Dirs: &util.ConfigDirs{Secrets: dir}}
}

func TestNormalizeSourceStorageKey_File(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"already canonical", "/tmp/semaphore/token", "/tmp/semaphore/token"},
		{"traversal segment", "/tmp/semaphore/../semaphore/token", "/tmp/semaphore/token"},
		{"nested traversal", "/tmp/a/b/../../semaphore/token", "/tmp/semaphore/token"},
		{"current dir segment", "/tmp/semaphore/./token", "/tmp/semaphore/token"},
		{"duplicated separators", "/tmp//semaphore///token", "/tmp/semaphore/token"},
		{"trailing separator", "/tmp/semaphore/token/", "/tmp/semaphore/token"},
		{"surrounding whitespace", "  /tmp/semaphore/token  ", "/tmp/semaphore/token"},
		{"traversal above root", "/../../tmp/semaphore/token", "/tmp/semaphore/token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeSourceStorageKey(AccessKeySourceStorageFile, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeSourceStorageKey_Rejects(t *testing.T) {
	tests := []struct {
		name        string
		storageType AccessKeySourceStorageType
		input       string
		errContains string
	}{
		{"relative path", AccessKeySourceStorageFile, "semaphore/token", "must be absolute"},
		{"traversal relative path", AccessKeySourceStorageFile, "../../etc/passwd", "must be absolute"},
		{"empty path", AccessKeySourceStorageFile, "", "must not be empty"},
		{"blank path", AccessKeySourceStorageFile, "   ", "must not be empty"},
		{"empty env name", AccessKeySourceStorageEnv, "  ", "must not be empty"},
		{"vault type", AccessKeySourceStorageVault, "/tmp/semaphore/token", "unsupported source storage type"},
		{"unknown type", AccessKeySourceStorageType("nope"), "x", "unsupported source storage type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeSourceStorageKey(tt.storageType, tt.input)
			assert.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestNormalizeSourceStorageKey_EnvKeepsPathCharactersVerbatim(t *testing.T) {
	// Environment variable names have no path semantics, so nothing may be
	// collapsed: "./FOO" and "FOO" are different variables.
	result, err := NormalizeSourceStorageKey(AccessKeySourceStorageEnv, "  ./VAULT_TOKEN  ")
	require.NoError(t, err)
	assert.Equal(t, "./VAULT_TOKEN", result)
}

func TestValidateSourceStorageKey_ContainmentInSecretsDir(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	t.Run("inside secrets dir", func(t *testing.T) {
		result, err := ValidateSourceStorageKey(
			AccessKeySourceStorageFile, filepath.Join(secrets, "token"))
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(secrets, "token"), result)
	})

	t.Run("traversal back into secrets dir is accepted after cleaning", func(t *testing.T) {
		result, err := ValidateSourceStorageKey(
			AccessKeySourceStorageFile, filepath.Join(secrets, "..", filepath.Base(secrets), "token"))
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(secrets, "token"), result)
	})

	t.Run("traversal out of secrets dir is rejected", func(t *testing.T) {
		_, err := ValidateSourceStorageKey(
			AccessKeySourceStorageFile, filepath.Join(secrets, "..", "..", "etc", "passwd"))
		assert.ErrorContains(t, err, "must be inside secrets path")
	})

	t.Run("unrelated absolute path is rejected", func(t *testing.T) {
		_, err := ValidateSourceStorageKey(AccessKeySourceStorageFile, "/etc/passwd")
		assert.ErrorContains(t, err, "must be inside secrets path")
	})

	t.Run("sibling with shared prefix is rejected", func(t *testing.T) {
		// "<secrets>-evil" shares a string prefix with the secrets dir but is not
		// inside it; a strings.HasPrefix check would wrongly accept it.
		_, err := ValidateSourceStorageKey(AccessKeySourceStorageFile, secrets+"-evil/token")
		assert.ErrorContains(t, err, "must be inside secrets path")
	})

	t.Run("env names are not containment checked", func(t *testing.T) {
		result, err := ValidateSourceStorageKey(AccessKeySourceStorageEnv, "VAULT_TOKEN")
		require.NoError(t, err)
		assert.Equal(t, "VAULT_TOKEN", result)
	})
}

func TestValidateSourceStorageKey_SkipsContainmentWhenUnconfigured(t *testing.T) {
	previous := util.Config
	t.Cleanup(func() { util.Config = previous })

	// Dirs is a pointer and is nil in minimally configured setups; the check must
	// degrade to normalization instead of panicking or refusing every write.
	util.Config = &util.ConfigType{}

	result, err := ValidateSourceStorageKey(AccessKeySourceStorageFile, "/tmp/semaphore/token")
	require.NoError(t, err)
	assert.Equal(t, "/tmp/semaphore/token", result)
}

func TestSourceStorageKeysReferToSameToken(t *testing.T) {
	tests := []struct {
		name        string
		storageType AccessKeySourceStorageType
		candidate   string
		stored      string
		expected    bool
	}{
		{"identical files", AccessKeySourceStorageFile,
			"/tmp/semaphore/token", "/tmp/semaphore/token", true},
		{"stored uses traversal", AccessKeySourceStorageFile,
			"/tmp/semaphore/token", "/tmp/semaphore/../semaphore/token", true},
		{"stored uses duplicated separators", AccessKeySourceStorageFile,
			"/tmp/semaphore/token", "/tmp//semaphore//token", true},
		{"stored uses dot segment", AccessKeySourceStorageFile,
			"/tmp/semaphore/token", "/tmp/semaphore/./token", true},
		{"different files", AccessKeySourceStorageFile,
			"/tmp/semaphore/token-a", "/tmp/semaphore/token-b", false},
		{"stored is relative and unnormalizable", AccessKeySourceStorageFile,
			"/tmp/semaphore/token", "semaphore/token", false},
		{"identical env names", AccessKeySourceStorageEnv,
			"VAULT_TOKEN", "VAULT_TOKEN", true},
		{"different env names", AccessKeySourceStorageEnv,
			"VAULT_TOKEN", "OTHER_TOKEN", false},
		{"env names are not path normalized", AccessKeySourceStorageEnv,
			"VAULT_TOKEN", "./VAULT_TOKEN", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected,
				SourceStorageKeysReferToSameToken(tt.storageType, tt.candidate, tt.stored))
		})
	}
}

func TestSourceStorageKeysReferToSameToken_Symlink(t *testing.T) {
	dir := t.TempDir()

	target := filepath.Join(dir, "real-token")
	require.NoError(t, os.WriteFile(target, []byte("s.token"), 0600))

	link := filepath.Join(dir, "link-token")
	require.NoError(t, os.Symlink(target, link))

	// Lexically these are two different paths, so only stat-based identity can
	// tell that both projects would end up reading the same token.
	assert.True(t, SourceStorageKeysReferToSameToken(AccessKeySourceStorageFile, link, target))
	assert.True(t, SourceStorageKeysReferToSameToken(AccessKeySourceStorageFile, target, link))

	other := filepath.Join(dir, "other-token")
	require.NoError(t, os.WriteFile(other, []byte("s.other"), 0600))

	assert.False(t, SourceStorageKeysReferToSameToken(AccessKeySourceStorageFile, other, target))
}

func TestSourceStorageKeysReferToSameToken_HardLink(t *testing.T) {
	dir := t.TempDir()

	target := filepath.Join(dir, "real-token")
	require.NoError(t, os.WriteFile(target, []byte("s.token"), 0600))

	link := filepath.Join(dir, "hard-token")
	require.NoError(t, os.Link(target, link))

	assert.True(t, SourceStorageKeysReferToSameToken(AccessKeySourceStorageFile, link, target))
}

func TestSourceStorageKeysReferToSameToken_MissingFilesFallBackToPaths(t *testing.T) {
	dir := t.TempDir()

	// A token file that does not exist yet must not make the comparison throw or
	// report a match; the lexical result still has to hold.
	missingA := filepath.Join(dir, "not-created-a")
	missingB := filepath.Join(dir, "not-created-b")

	assert.False(t, SourceStorageKeysReferToSameToken(AccessKeySourceStorageFile, missingA, missingB))
	assert.True(t, SourceStorageKeysReferToSameToken(
		AccessKeySourceStorageFile, missingA, filepath.Join(dir, ".", "not-created-a")))
}
