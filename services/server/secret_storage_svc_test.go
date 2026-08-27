package server

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	victimProjectID   = 1
	attackerProjectID = 2
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

// --- test doubles ---------------------------------------------------------

type storageSvcSecretStorageRepo struct {
	nextID   int
	created  []db.SecretStorage
	updated  []db.SecretStorage
	deleted  []int
	storages map[int]db.SecretStorage
}

func (m *storageSvcSecretStorageRepo) CreateSecretStorage(storage db.SecretStorage) (db.SecretStorage, error) {
	m.nextID++
	storage.ID = m.nextID
	m.created = append(m.created, storage)
	if m.storages == nil {
		m.storages = map[int]db.SecretStorage{}
	}
	m.storages[storage.ID] = storage
	return storage, nil
}

func (m *storageSvcSecretStorageRepo) UpdateSecretStorage(storage db.SecretStorage) error {
	m.updated = append(m.updated, storage)
	return nil
}

func (m *storageSvcSecretStorageRepo) GetSecretStorage(_ int, storageID int) (db.SecretStorage, error) {
	if storage, ok := m.storages[storageID]; ok {
		return storage, nil
	}
	return db.SecretStorage{}, db.ErrNotFound
}

func (m *storageSvcSecretStorageRepo) DeleteSecretStorage(_ int, storageID int) error {
	m.deleted = append(m.deleted, storageID)
	return nil
}

func (m *storageSvcSecretStorageRepo) GetSecretStorages(int) ([]db.SecretStorage, error) {
	return nil, nil
}

func (m *storageSvcSecretStorageRepo) GetSecretStorageRefs(int, int) (db.ObjectReferrers, error) {
	return db.ObjectReferrers{}, nil
}

// storageSvcAccessKeyRepo answers the cross-project token lookup. tokenKeysPerCall
// lets a test return a different answer to the pre-write and post-write checks,
// which is how a concurrent claim by another node is simulated.
type storageSvcAccessKeyRepo struct {
	tokenKeys        []db.AccessKey
	tokenKeysPerCall [][]db.AccessKey
	tokenKeyCalls    int
	tokenKeysErr     error
	updated          []db.AccessKey
}

func (m *storageSvcAccessKeyRepo) GetAccessKeysBySourceStorageType(db.AccessKeySourceStorageType) ([]db.AccessKey, error) {
	call := m.tokenKeyCalls
	m.tokenKeyCalls++

	if m.tokenKeysErr != nil {
		return nil, m.tokenKeysErr
	}

	if m.tokenKeysPerCall != nil {
		if call < len(m.tokenKeysPerCall) {
			return m.tokenKeysPerCall[call], nil
		}
		return m.tokenKeysPerCall[len(m.tokenKeysPerCall)-1], nil
	}

	return m.tokenKeys, nil
}

func (m *storageSvcAccessKeyRepo) UpdateAccessKey(key db.AccessKey) error {
	m.updated = append(m.updated, key)
	return nil
}

func (m *storageSvcAccessKeyRepo) GetAccessKey(int, int) (db.AccessKey, error) {
	return db.AccessKey{}, db.ErrNotFound
}
func (m *storageSvcAccessKeyRepo) GetAccessKeyRefs(int, int) (db.ObjectReferrers, error) {
	return db.ObjectReferrers{}, nil
}
func (m *storageSvcAccessKeyRepo) GetAccessKeys(int, db.GetAccessKeyOptions, db.RetrieveQueryParams) ([]db.AccessKey, error) {
	return nil, nil
}
func (m *storageSvcAccessKeyRepo) CreateAccessKey(k db.AccessKey) (db.AccessKey, error) {
	return k, nil
}
func (m *storageSvcAccessKeyRepo) DeleteAccessKey(int, int) error { return nil }
func (m *storageSvcAccessKeyRepo) GetTaskAccessKey(int, int) (db.AccessKey, error) {
	return db.AccessKey{}, db.ErrNotFound
}
func (m *storageSvcAccessKeyRepo) DeleteTaskAccessKeys(int, int) error { return nil }
func (m *storageSvcAccessKeyRepo) DeleteExpiredTaskAccessKeys() error  { return nil }

type storageSvcAccessKeyService struct {
	nextID   int
	existing []db.AccessKey
	created  []db.AccessKey
	updated  []db.AccessKey
	deleted  []int
}

func (m *storageSvcAccessKeyService) Create(key db.AccessKey) (db.AccessKey, error) {
	m.nextID++
	key.ID = m.nextID
	m.created = append(m.created, key)
	return key, nil
}

func (m *storageSvcAccessKeyService) Update(key db.AccessKey) error {
	m.updated = append(m.updated, key)
	return nil
}

func (m *storageSvcAccessKeyService) GetAll(int, db.GetAccessKeyOptions, db.RetrieveQueryParams) ([]db.AccessKey, error) {
	return m.existing, nil
}

func (m *storageSvcAccessKeyService) Delete(_ int, keyID int) error {
	m.deleted = append(m.deleted, keyID)
	return nil
}

// --- helpers --------------------------------------------------------------

type storageSvcFixture struct {
	service   SecretStorageService
	storages  *storageSvcSecretStorageRepo
	keyRepo   *storageSvcAccessKeyRepo
	keyServic *storageSvcAccessKeyService
}

func newStorageSvcFixture() *storageSvcFixture {
	storages := &storageSvcSecretStorageRepo{}
	keyRepo := &storageSvcAccessKeyRepo{}
	keyService := &storageSvcAccessKeyService{}

	return &storageSvcFixture{
		service: &SecretStorageServiceImpl{
			secretStorageRepo: storages,
			accessKeyRepo:     keyRepo,
			accessKeyService:  keyService,
		},
		storages:  storages,
		keyRepo:   keyRepo,
		keyServic: keyService,
	}
}

// tokenKey builds the access key a project's vault storage owns.
func tokenKey(projectID int, storageType db.AccessKeySourceStorageType, key string) db.AccessKey {
	pid := projectID
	st := storageType
	return db.AccessKey{
		ID:                100 + projectID,
		Name:              "vault-token",
		Type:              db.AccessKeyString,
		ProjectID:         &pid,
		Owner:             db.AccessKeySecretStorage,
		SourceStorageType: &st,
		SourceStorageKey:  &key,
	}
}

func fileStorage(projectID int, secret string) db.SecretStorage {
	st := db.AccessKeySourceStorageFile
	return db.SecretStorage{
		ProjectID:         projectID,
		Name:              "vault",
		Type:              db.SecretStorageTypeVault,
		SourceStorageType: &st,
		Secret:            secret,
	}
}

// --- Create ---------------------------------------------------------------

func TestSecretStorageService_Create_RejectsTokenClaimedByAnotherProject(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	victimToken := filepath.Join(secrets, "vault-token-projA")

	// Every spelling below resolves to the victim project's token file. Storing the
	// string as typed would let each one slip past an equality check.
	tests := []struct {
		name    string
		attempt string
	}{
		{"identical path", victimToken},
		{"traversal segment", filepath.Join(secrets, "..", filepath.Base(secrets), "vault-token-projA")},
		{"dot segment", filepath.Join(secrets, ".", "vault-token-projA")},
		{"duplicated separators", secrets + "//vault-token-projA"},
		{"trailing separator", victimToken + "/"},
		{"deep traversal", filepath.Join(secrets, "a", "b", "..", "..", "vault-token-projA")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newStorageSvcFixture()
			f.keyRepo.tokenKeys = []db.AccessKey{
				tokenKey(victimProjectID, db.AccessKeySourceStorageFile, victimToken),
			}

			_, err := f.service.Create(fileStorage(attackerProjectID, tt.attempt))

			assert.ErrorContains(t, err, "already used by another project")
			assert.Empty(t, f.storages.created, "no storage may be persisted for a rejected claim")
			assert.Empty(t, f.keyServic.created, "no access key may be persisted for a rejected claim")
		})
	}
}

func TestSecretStorageService_Create_AllowsReuseWithinSameProject(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	token := filepath.Join(secrets, "vault-token")

	f := newStorageSvcFixture()
	f.keyRepo.tokenKeys = []db.AccessKey{
		tokenKey(victimProjectID, db.AccessKeySourceStorageFile, token),
	}

	// Two storages of one project sharing a token stay inside a single trust
	// boundary, so this must keep working.
	_, err := f.service.Create(fileStorage(victimProjectID, token))

	require.NoError(t, err)
	assert.Len(t, f.keyServic.created, 1)
}

func TestSecretStorageService_Create_AllowsUnclaimedToken(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	f := newStorageSvcFixture()
	f.keyRepo.tokenKeys = []db.AccessKey{
		tokenKey(victimProjectID, db.AccessKeySourceStorageFile, filepath.Join(secrets, "token-a")),
	}

	_, err := f.service.Create(fileStorage(attackerProjectID, filepath.Join(secrets, "token-b")))

	require.NoError(t, err)
	require.Len(t, f.keyServic.created, 1)
	assert.Equal(t, filepath.Join(secrets, "token-b"), *f.keyServic.created[0].SourceStorageKey)
}

func TestSecretStorageService_Create_PersistsCanonicalPath(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	f := newStorageSvcFixture()

	_, err := f.service.Create(fileStorage(
		victimProjectID, filepath.Join(secrets, "sub", "..", ".", "token")))

	require.NoError(t, err)
	require.Len(t, f.keyServic.created, 1)
	// The row must hold the canonical form, otherwise a later project could claim
	// the same file under a different spelling.
	assert.Equal(t, filepath.Join(secrets, "token"), *f.keyServic.created[0].SourceStorageKey)
}

func TestSecretStorageService_Create_RejectsPathOutsideSecretsDir(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	f := newStorageSvcFixture()

	_, err := f.service.Create(fileStorage(attackerProjectID, "/etc/vault-token"))

	assert.ErrorContains(t, err, "must be inside secrets path")
	assert.Empty(t, f.storages.created)
}

func TestSecretStorageService_Create_RejectsRelativePath(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	f := newStorageSvcFixture()

	_, err := f.service.Create(fileStorage(attackerProjectID, "../../etc/vault-token"))

	assert.ErrorContains(t, err, "must be absolute")
	assert.Empty(t, f.storages.created)
}

func TestSecretStorageService_Create_RejectsEnvVarClaimedByAnotherProject(t *testing.T) {
	withSecretsDir(t, t.TempDir())

	f := newStorageSvcFixture()
	f.keyRepo.tokenKeys = []db.AccessKey{
		tokenKey(victimProjectID, db.AccessKeySourceStorageEnv, "VAULT_TOKEN_PROJ_A"),
	}

	envType := db.AccessKeySourceStorageEnv
	_, err := f.service.Create(db.SecretStorage{
		ProjectID:         attackerProjectID,
		Name:              "vault",
		Type:              db.SecretStorageTypeVault,
		SourceStorageType: &envType,
		Secret:            "  VAULT_TOKEN_PROJ_A  ",
	})

	assert.ErrorContains(t, err, "already used by another project")
	assert.Empty(t, f.storages.created)
}

func TestSecretStorageService_Create_RollsBackWhenTokenClaimedDuringWrite(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	token := filepath.Join(secrets, "vault-token")

	f := newStorageSvcFixture()
	// The pre-write check sees nothing; by the time the row is written another node
	// has claimed the same token.
	f.keyRepo.tokenKeysPerCall = [][]db.AccessKey{
		{},
		{tokenKey(victimProjectID, db.AccessKeySourceStorageFile, token)},
	}

	res, err := f.service.Create(fileStorage(attackerProjectID, token))

	assert.ErrorContains(t, err, "already used by another project")
	assert.Equal(t, []int{res.ID}, f.storages.deleted, "the losing claim must be withdrawn")
}

func TestSecretStorageService_Create_LocalStorageSkipsTokenChecks(t *testing.T) {
	withSecretsDir(t, t.TempDir())

	f := newStorageSvcFixture()

	// Local storage keeps its secret in Semaphore; there is no shared token to claim.
	_, err := f.service.Create(db.SecretStorage{
		ProjectID: attackerProjectID,
		Name:      "local",
		Type:      db.SecretStorageTypeLocal,
		Secret:    "plain-secret",
	})

	require.NoError(t, err)
	require.Len(t, f.keyServic.created, 1)
	assert.Equal(t, "plain-secret", f.keyServic.created[0].String)
	assert.Nil(t, f.keyServic.created[0].SourceStorageKey)
	assert.Equal(t, 0, f.keyRepo.tokenKeyCalls)
}

func TestSecretStorageService_Create_RequiresSecret(t *testing.T) {
	withSecretsDir(t, t.TempDir())

	f := newStorageSvcFixture()

	_, err := f.service.Create(fileStorage(attackerProjectID, ""))

	assert.ErrorContains(t, err, "secret must be set")
}

func TestSecretStorageService_Create_PropagatesLookupFailure(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	f := newStorageSvcFixture()
	f.keyRepo.tokenKeysErr = errors.New("database is down")

	// A lookup that cannot answer must not be read as "nobody claimed it".
	_, err := f.service.Create(fileStorage(attackerProjectID, filepath.Join(secrets, "token")))

	assert.ErrorContains(t, err, "database is down")
	assert.Empty(t, f.storages.created)
}

// --- Update ---------------------------------------------------------------

func TestSecretStorageService_Update_RejectsRepointingToAnotherProjectsToken(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	victimToken := filepath.Join(secrets, "vault-token-projA")

	tests := []struct {
		name    string
		attempt string
	}{
		{"identical path", victimToken},
		{"traversal segment", filepath.Join(secrets, "..", filepath.Base(secrets), "vault-token-projA")},
		{"duplicated separators", secrets + "//vault-token-projA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newStorageSvcFixture()
			f.keyRepo.tokenKeys = []db.AccessKey{
				tokenKey(victimProjectID, db.AccessKeySourceStorageFile, victimToken),
			}
			f.keyServic.existing = []db.AccessKey{
				tokenKey(attackerProjectID, db.AccessKeySourceStorageFile,
					filepath.Join(secrets, "vault-token-projB")),
			}

			storage := fileStorage(attackerProjectID, tt.attempt)
			storage.ID = 7

			err := f.service.Update(storage)

			assert.ErrorContains(t, err, "already used by another project")
			assert.Empty(t, f.keyServic.updated, "the key must keep pointing at its own token")
		})
	}
}

func TestSecretStorageService_Update_AllowsOwnToken(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	ownToken := filepath.Join(secrets, "vault-token-projB")

	f := newStorageSvcFixture()
	f.keyRepo.tokenKeys = []db.AccessKey{
		tokenKey(victimProjectID, db.AccessKeySourceStorageFile, filepath.Join(secrets, "vault-token-projA")),
		tokenKey(attackerProjectID, db.AccessKeySourceStorageFile, ownToken),
	}
	f.keyServic.existing = []db.AccessKey{
		tokenKey(attackerProjectID, db.AccessKeySourceStorageFile, ownToken),
	}

	storage := fileStorage(attackerProjectID, ownToken)
	storage.ID = 7

	// Re-saving a storage without changing its token must not trip over its own claim.
	require.NoError(t, f.service.Update(storage))
	require.Len(t, f.keyServic.updated, 1)
	assert.Equal(t, ownToken, *f.keyServic.updated[0].SourceStorageKey)
}

func TestSecretStorageService_Update_PersistsCanonicalPath(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	f := newStorageSvcFixture()
	f.keyServic.existing = []db.AccessKey{
		tokenKey(victimProjectID, db.AccessKeySourceStorageFile, filepath.Join(secrets, "old-token")),
	}

	storage := fileStorage(victimProjectID, filepath.Join(secrets, "sub", "..", "token"))
	storage.ID = 7

	require.NoError(t, f.service.Update(storage))
	require.Len(t, f.keyServic.updated, 1)
	assert.Equal(t, filepath.Join(secrets, "token"), *f.keyServic.updated[0].SourceStorageKey)
}

func TestSecretStorageService_Update_EmptySecretLeavesKeyUntouched(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	f := newStorageSvcFixture()
	f.keyServic.existing = []db.AccessKey{
		tokenKey(victimProjectID, db.AccessKeySourceStorageFile, filepath.Join(secrets, "token")),
	}

	storage := fileStorage(victimProjectID, "")
	storage.ID = 7

	// An empty token means "keep the current one", so renaming a storage must not
	// be blocked by the token another project might hold.
	require.NoError(t, f.service.Update(storage))
	assert.Empty(t, f.keyServic.updated)
	assert.Empty(t, f.keyServic.created)
	assert.Equal(t, 0, f.keyRepo.tokenKeyCalls)
}

func TestSecretStorageService_Update_CreatesKeyWhenMissing(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	f := newStorageSvcFixture()
	f.keyServic.existing = nil

	storage := fileStorage(victimProjectID, filepath.Join(secrets, "token"))
	storage.ID = 7

	require.NoError(t, f.service.Update(storage))
	require.Len(t, f.keyServic.created, 1)
	assert.Equal(t, filepath.Join(secrets, "token"), *f.keyServic.created[0].SourceStorageKey)
}

func TestSecretStorageService_Update_RestoresPreviousKeyWhenTokenClaimedDuringWrite(t *testing.T) {
	secrets := t.TempDir()
	withSecretsDir(t, secrets)

	token := filepath.Join(secrets, "vault-token")
	previous := tokenKey(attackerProjectID, db.AccessKeySourceStorageFile,
		filepath.Join(secrets, "own-token"))

	f := newStorageSvcFixture()
	f.keyServic.existing = []db.AccessKey{previous}
	f.keyRepo.tokenKeysPerCall = [][]db.AccessKey{
		{},
		{tokenKey(victimProjectID, db.AccessKeySourceStorageFile, token)},
	}

	storage := fileStorage(attackerProjectID, token)
	storage.ID = 7

	err := f.service.Update(storage)

	assert.ErrorContains(t, err, "already used by another project")
	require.Len(t, f.keyRepo.updated, 1, "the previous token reference must be restored")
	assert.Equal(t, *previous.SourceStorageKey, *f.keyRepo.updated[0].SourceStorageKey)
	assert.True(t, f.keyRepo.updated[0].OverrideSecret)
}
