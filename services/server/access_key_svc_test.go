package server

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/semaphoreui/semaphore/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keySvcAccessKeyRepo records what reaches the store and answers the cross-project
// source lookup.
type keySvcAccessKeyRepo struct {
	sourceKeys      []db.AccessKey
	sourceKeyCalls  int
	sourceKeysErr   error
	existing        db.AccessKey
	existingErr     error
	created         []db.AccessKey
	updated         []db.AccessKey
	createAccessErr error
}

func (m *keySvcAccessKeyRepo) GetAccessKeysBySourceStorageType(db.AccessKeySourceStorageType) ([]db.AccessKey, error) {
	m.sourceKeyCalls++
	if m.sourceKeysErr != nil {
		return nil, m.sourceKeysErr
	}
	return m.sourceKeys, nil
}

func (m *keySvcAccessKeyRepo) CreateAccessKey(k db.AccessKey) (db.AccessKey, error) {
	if m.createAccessErr != nil {
		return db.AccessKey{}, m.createAccessErr
	}
	k.ID = len(m.created) + 1
	m.created = append(m.created, k)
	return k, nil
}

func (m *keySvcAccessKeyRepo) UpdateAccessKey(k db.AccessKey) error {
	m.updated = append(m.updated, k)
	return nil
}

func (m *keySvcAccessKeyRepo) GetAccessKey(int, int) (db.AccessKey, error) {
	return m.existing, m.existingErr
}

func (m *keySvcAccessKeyRepo) GetAccessKeyRefs(int, int) (db.ObjectReferrers, error) {
	return db.ObjectReferrers{}, nil
}
func (m *keySvcAccessKeyRepo) GetAccessKeys(int, db.GetAccessKeyOptions, db.RetrieveQueryParams) ([]db.AccessKey, error) {
	return nil, nil
}
func (m *keySvcAccessKeyRepo) DeleteAccessKey(int, int) error { return nil }
func (m *keySvcAccessKeyRepo) GetTaskAccessKey(int, int) (db.AccessKey, error) {
	return db.AccessKey{}, db.ErrNotFound
}
func (m *keySvcAccessKeyRepo) DeleteTaskAccessKeys(int, int) error { return nil }
func (m *keySvcAccessKeyRepo) DeleteExpiredTaskAccessKeys() error  { return nil }

func newKeyService(repo *keySvcAccessKeyRepo) AccessKeyService {
	return NewAccessKeyService(repo, NewAccessKeyEncryptionService(nil, nil, nil, nil), nil)
}

// fileKey builds a key that reads its value from a file on disk.
func fileKey(projectID int, id int, path string) db.AccessKey {
	pid := projectID
	st := db.AccessKeySourceStorageFile
	return db.AccessKey{
		ID:                id,
		Name:              "token",
		Type:              db.AccessKeyString,
		ProjectID:         &pid,
		SourceStorageType: &st,
		SourceStorageKey:  &path,
	}
}

// The key endpoints (POST/PUT /api/project/{id}/keys) bind SourceStorageKey and
// SourceStorageType straight from the request body, so the rule has to hold in the
// service rather than in the secret storage service alone.

func TestAccessKeyService_Create_RejectsSourceClaimedByAnotherProject(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	victimToken := filepath.Join(secrets, "vault-token-projA")

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
			repo := &keySvcAccessKeyRepo{
				sourceKeys: []db.AccessKey{fileKey(victimProjectID, 1, victimToken)},
			}

			_, err := newKeyService(repo).Create(fileKey(attackerProjectID, 0, tt.attempt))

			assert.ErrorContains(t, err, "already used by another project")
			assert.Empty(t, repo.created, "the key must not reach the store")
		})
	}
}

func TestAccessKeyService_Create_PersistsCanonicalSourceKey(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	repo := &keySvcAccessKeyRepo{}

	_, err := newKeyService(repo).Create(
		fileKey(victimProjectID, 0, filepath.Join(secrets, "sub", "..", ".", "token")))

	require.NoError(t, err)
	require.Len(t, repo.created, 1)
	assert.Equal(t, filepath.Join(secrets, "token"), *repo.created[0].SourceStorageKey)
}

func TestAccessKeyService_Create_AllowsReuseWithinSameProject(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	token := filepath.Join(secrets, "token")

	repo := &keySvcAccessKeyRepo{
		sourceKeys: []db.AccessKey{fileKey(victimProjectID, 1, token)},
	}

	_, err := newKeyService(repo).Create(fileKey(victimProjectID, 0, token))

	require.NoError(t, err)
	assert.Len(t, repo.created, 1)
}

func TestAccessKeyService_Create_RejectsPathOutsideSecretsDir(t *testing.T) {
	withSecretsDir(t, t.TempDir())

	repo := &keySvcAccessKeyRepo{}

	_, err := newKeyService(repo).Create(fileKey(attackerProjectID, 0, "/etc/shadow"))

	assert.ErrorContains(t, err, "must be inside secrets path")
	assert.Empty(t, repo.created)
}

func TestAccessKeyService_Create_RejectsEnvVarClaimedByAnotherProject(t *testing.T) {
	withSecretsDir(t, t.TempDir())

	pid := victimProjectID
	envType := db.AccessKeySourceStorageEnv
	name := "VAULT_TOKEN_PROJ_A"

	repo := &keySvcAccessKeyRepo{
		sourceKeys: []db.AccessKey{{
			ID:                1,
			ProjectID:         &pid,
			SourceStorageType: &envType,
			SourceStorageKey:  &name,
		}},
	}

	attacker := attackerProjectID
	padded := "  VAULT_TOKEN_PROJ_A  "
	_, err := newKeyService(repo).Create(db.AccessKey{
		Name:              "token",
		Type:              db.AccessKeyString,
		ProjectID:         &attacker,
		SourceStorageType: &envType,
		SourceStorageKey:  &padded,
	})

	assert.ErrorContains(t, err, "already used by another project")
	assert.Empty(t, repo.created)
}

func TestAccessKeyService_Create_IgnoresVaultSourceType(t *testing.T) {
	withSecretsDir(t, t.TempDir())

	pid := victimProjectID
	vaultType := db.AccessKeySourceStorageVault
	path := "secret/data/token"
	storageID := 3

	repo := &keySvcAccessKeyRepo{}
	svc := newKeyService(repo).(*AccessKeyServiceImpl)

	key := db.AccessKey{
		Name:              "token",
		Type:              db.AccessKeyString,
		ProjectID:         &pid,
		SourceStorageType: &vaultType,
		SourceStorageID:   &storageID,
		SourceStorageKey:  &path,
	}

	// Vault paths are addressed through SourceStorageID, which already belongs to
	// one project, so they must not be subject to the cross-project file rule — nor
	// rewritten by a path canonicalizer that would corrupt them.
	require.NoError(t, svc.claimSourceStorageKey(&key))
	assert.Equal(t, 0, repo.sourceKeyCalls)
	assert.Equal(t, "secret/data/token", *key.SourceStorageKey)
}

func TestAccessKeyService_Create_PropagatesLookupFailure(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	repo := &keySvcAccessKeyRepo{sourceKeysErr: errors.New("database is down")}

	// A lookup that cannot answer must not be read as "nobody claimed it".
	_, err := newKeyService(repo).Create(fileKey(attackerProjectID, 0, filepath.Join(secrets, "token")))

	assert.ErrorContains(t, err, "database is down")
	assert.Empty(t, repo.created)
}

func TestAccessKeyService_Update_RejectsRepointingAtAnotherProjectsToken(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	victimToken := filepath.Join(secrets, "vault-token-projA")
	attacker := attackerProjectID

	repo := &keySvcAccessKeyRepo{
		sourceKeys: []db.AccessKey{fileKey(victimProjectID, 1, victimToken)},
		// The attacker's own key stores its token inline, so SourceStorageType is
		// nil and the "cannot override secret storage" guard does not apply to it.
		existing: db.AccessKey{
			ID:        9,
			Name:      "token",
			Type:      db.AccessKeyString,
			ProjectID: &attacker,
			Owner:     db.AccessKeySecretStorage,
		},
	}

	update := fileKey(attackerProjectID, 9, filepath.Join(secrets, "..", filepath.Base(secrets), "vault-token-projA"))
	update.Owner = db.AccessKeySecretStorage
	update.OverrideSecret = true

	err := newKeyService(repo).Update(update)

	assert.ErrorContains(t, err, "already used by another project")
	assert.Empty(t, repo.updated, "the key must keep pointing at its own token")
}

func TestAccessKeyService_Update_PersistsCanonicalSourceKey(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	pid := victimProjectID
	repo := &keySvcAccessKeyRepo{
		existing: db.AccessKey{ID: 9, Name: "token", Type: db.AccessKeyString, ProjectID: &pid},
	}

	update := fileKey(victimProjectID, 9, filepath.Join(secrets, "sub", "..", "token"))
	update.OverrideSecret = true

	require.NoError(t, newKeyService(repo).Update(update))
	require.Len(t, repo.updated, 1)
	assert.Equal(t, filepath.Join(secrets, "token"), *repo.updated[0].SourceStorageKey)
}

func TestAccessKeyService_Update_SkipsCheckWithoutOverrideSecret(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	repo := &keySvcAccessKeyRepo{
		sourceKeys: []db.AccessKey{
			fileKey(victimProjectID, 1, filepath.Join(secrets, "vault-token-projA")),
		},
	}

	// Without OverrideSecret the source storage columns are not written, so renaming
	// a key must not be rejected over a source it is not actually claiming.
	update := fileKey(attackerProjectID, 9, filepath.Join(secrets, "vault-token-projA"))
	update.OverrideSecret = false

	require.NoError(t, newKeyService(repo).Update(update))
	assert.Equal(t, 0, repo.sourceKeyCalls)
	assert.Len(t, repo.updated, 1)
}
