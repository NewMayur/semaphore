package project

import (
	"path/filepath"
	"testing"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/sql"
	proFactory "github.com/semaphoreui/semaphore/pro/db/factory"
	"github.com/semaphoreui/semaphore/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Restore writes access keys straight to the store instead of going through
// AccessKeyService, so a crafted backup would otherwise reintroduce the
// cross-project vault token leak the service closes.

func restoreTestStore(t *testing.T, secretsDir string) (db.Store, db.User) {
	t.Helper()

	previous := util.Config
	t.Cleanup(func() { util.Config = previous })

	store := sql.InitConfigCreateTestStore()
	util.Config.TmpPath = "/tmp"
	util.Config.Dirs = &util.ConfigDirs{Secrets: secretsDir}

	user, err := store.CreateUser(db.UserWithPwd{
		Pwd: "3412341234123",
		User: db.User{
			Username: "restorer",
			Name:     "Restorer",
			Email:    "restorer@example.com",
			Admin:    true,
		},
	})
	require.NoError(t, err)

	return store, user
}

// victimKeyPath creates a project that already reads its vault token from a file
// and returns that path.
func victimKeyPath(t *testing.T, store db.Store, secrets string) string {
	t.Helper()

	proj, err := store.CreateProject(db.Project{Name: "victim"})
	require.NoError(t, err)

	path := filepath.Join(secrets, "vault-token-projA")
	fileType := db.AccessKeySourceStorageFile

	_, err = store.CreateAccessKey(db.AccessKey{
		Name:              "victim-token",
		Type:              db.AccessKeyString,
		ProjectID:         &proj.ID,
		Owner:             db.AccessKeySecretStorage,
		SourceStorageType: &fileType,
		SourceStorageKey:  &path,
	})
	require.NoError(t, err)

	return path
}

func backupWithSourceStorageKey(name string, sourceKey string) *BackupFormat {
	fileType := db.AccessKeySourceStorageFile

	return &BackupFormat{
		Meta: BackupMeta{Project: db.Project{Name: name}},
		Keys: []BackupAccessKey{{
			AccessKey: db.AccessKey{
				Name:              "stolen-token",
				Type:              db.AccessKeyString,
				Owner:             db.AccessKeySecretStorage,
				SourceStorageType: &fileType,
				SourceStorageKey:  &sourceKey,
			},
		}},
	}
}

func TestRestore_RejectsSourceStorageKeyClaimedByAnotherProject(t *testing.T) {
	secrets := t.TempDir()
	store, user := restoreTestStore(t, secrets)
	victimToken := victimKeyPath(t, store, secrets)

	tests := []struct {
		name    string
		attempt string
	}{
		{"identical path", victimToken},
		{"traversal segment", filepath.Join(secrets, "..", filepath.Base(secrets), "vault-token-projA")},
		{"dot segment", filepath.Join(secrets, ".", "vault-token-projA")},
		{"duplicated separators", secrets + "//vault-token-projA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := backupWithSourceStorageKey("attacker-"+tt.name, tt.attempt).Restore(user, store, proFactory.NewWorkflowStore(store))

			assert.ErrorContains(t, err, "already used by another project")
		})
	}
}

func TestRestore_RejectsSourceStorageKeyOutsideSecretsDir(t *testing.T) {
	secrets := t.TempDir()
	store, user := restoreTestStore(t, secrets)

	_, err := backupWithSourceStorageKey("attacker-outside", "/etc/vault-token").
		Restore(user, store, proFactory.NewWorkflowStore(store))

	assert.ErrorContains(t, err, "must be inside secrets path")
}

func TestRestore_CanonicalizesSourceStorageKey(t *testing.T) {
	secrets := t.TempDir()
	store, user := restoreTestStore(t, secrets)

	proj, err := backupWithSourceStorageKey("legit", filepath.Join(secrets, "sub", "..", ".", "token")).
		Restore(user, store, proFactory.NewWorkflowStore(store))
	require.NoError(t, err)

	keys, err := store.GetAccessKeys(proj.ID, db.GetAccessKeyOptions{IgnoreOwner: true}, db.RetrieveQueryParams{})
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, filepath.Join(secrets, "token"), *keys[0].SourceStorageKey)
}

func TestRestore_AllowsUnclaimedSourceStorageKey(t *testing.T) {
	secrets := t.TempDir()
	store, user := restoreTestStore(t, secrets)
	victimKeyPath(t, store, secrets)

	// A path nobody else uses must still restore, so legitimate file-based setups
	// keep working.
	proj, err := backupWithSourceStorageKey("legit", filepath.Join(secrets, "vault-token-projB")).
		Restore(user, store, proFactory.NewWorkflowStore(store))
	require.NoError(t, err)

	keys, err := store.GetAccessKeys(proj.ID, db.GetAccessKeyOptions{IgnoreOwner: true}, db.RetrieveQueryParams{})
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, filepath.Join(secrets, "vault-token-projB"), *keys[0].SourceStorageKey)
}
