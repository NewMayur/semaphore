package server

import (
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/pkg/common_errors"
	"github.com/semaphoreui/semaphore/pkg/random"
	pro "github.com/semaphoreui/semaphore/pro/services/server"
)

type SecretStorageService interface {
	GetSecretStorage(projectID int, storageID int) (db.SecretStorage, error)
	Update(storage db.SecretStorage) error
	Delete(projectID int, storageID int) error
	GetSecretStorages(projectID int) ([]db.SecretStorage, error)
	Create(storage db.SecretStorage) (res db.SecretStorage, err error)
	SyncSecrets(sync db.SecretSync) error
}

func NewSecretStorageService(
	secretStorageRepo db.SecretStorageRepository,
	accessKeyRepo db.AccessKeyManager,
	accessKeyService AccessKeyService,
	encryptionService AccessKeyEncryptionService,
) SecretStorageService {
	return &SecretStorageServiceImpl{
		secretStorageRepo: secretStorageRepo,
		accessKeyRepo:     accessKeyRepo,
		accessKeyService:  accessKeyService,
		encryptionService: encryptionService,
	}
}

type SecretStorageServiceImpl struct {
	secretStorageRepo db.SecretStorageRepository
	accessKeyRepo     db.AccessKeyManager
	accessKeyService  AccessKeyService
	encryptionService AccessKeyEncryptionService
}

func (s *SecretStorageServiceImpl) SyncSecrets(sync db.SecretSync) error {
	return pro.SyncSecrets(sync, s.secretStorageRepo, s.accessKeyRepo, s.encryptionService)
}

func (s *SecretStorageServiceImpl) Delete(projectID int, storageID int) (err error) {
	storage, err := s.secretStorageRepo.GetSecretStorage(projectID, storageID)
	if err != nil {
		return
	}

	if storage.SyncEnabled {
		var syncedKeys []db.AccessKey
		syncedKeys, err = s.accessKeyRepo.GetAccessKeys(projectID, db.GetAccessKeyOptions{
			IgnoreOwner:     true,
			SourceStorageID: &storageID,
		}, db.RetrieveQueryParams{})
		if err != nil {
			return
		}

		for _, key := range syncedKeys {
			if err = s.accessKeyRepo.DeleteAccessKey(projectID, key.ID); err != nil {
				return
			}
		}
	}

	err = s.secretStorageRepo.DeleteSecretStorage(projectID, storageID)
	if err != nil {
		return
	}

	keys, err := s.accessKeyService.GetAll(projectID, db.GetAccessKeyOptions{
		Owner:     db.AccessKeySecretStorage,
		StorageID: &storageID,
	}, db.RetrieveQueryParams{})

	if err != nil {
		return
	}

	for _, key := range keys {
		err = s.accessKeyService.Delete(projectID, key.ID)
	}

	return
}

func (s *SecretStorageServiceImpl) GetSecretStorage(projectID int, storageID int) (res db.SecretStorage, err error) {
	return s.secretStorageRepo.GetSecretStorage(projectID, storageID)
}

// resolveSourceStorageKey validates the reference a secret storage uses to locate
// its vault token and returns it in canonical form.
//
// AccessKeyService enforces the same rule when the key is written, and that is what
// actually guarantees it. Checking here as well keeps the storage row from being
// created only to be rolled back, and reports the rejection against the field the
// user filled in.
func (s *SecretStorageServiceImpl) resolveSourceStorageKey(
	sourceStorageType db.AccessKeySourceStorageType,
	secret string,
	projectID int,
) (canonicalKey string, err error) {
	canonicalKey, err = db.ValidateSourceStorageKey(sourceStorageType, secret)
	if err != nil {
		return "", err
	}

	if err = s.checkSourceStorageKeyUnclaimed(sourceStorageType, canonicalKey, projectID); err != nil {
		return "", err
	}

	return canonicalKey, nil
}

// checkSourceStorageKeyUnclaimed fails when a project other than projectID already
// takes its vault token from the same file or environment variable.
func (s *SecretStorageServiceImpl) checkSourceStorageKeyUnclaimed(
	sourceStorageType db.AccessKeySourceStorageType,
	canonicalKey string,
	projectID int,
) error {
	keys, err := s.accessKeyRepo.GetAccessKeysBySourceStorageType(sourceStorageType)
	if err != nil {
		return err
	}

	if db.FindConflictingSourceStorageKey(keys, sourceStorageType, canonicalKey, &projectID, 0) != nil {
		return db.ErrSourceStorageKeyClaimed
	}

	return nil
}

// confirmSourceStorageKeyClaim re-runs the cross-project check once the access key
// has been written. The check and the write are not atomic, so a request in another
// project — including one on another node of an HA cluster — can claim the same
// token in between. When that happened, rollback undoes this write; both racers
// backing out is the safe outcome, and the operator simply retries.
func (s *SecretStorageServiceImpl) confirmSourceStorageKeyClaim(
	sourceStorageType *db.AccessKeySourceStorageType,
	canonicalKey string,
	projectID int,
	rollback func() error,
) error {
	if sourceStorageType == nil || canonicalKey == "" {
		return nil
	}

	conflictErr := s.checkSourceStorageKeyUnclaimed(*sourceStorageType, canonicalKey, projectID)
	if conflictErr == nil {
		return nil
	}

	if rollbackErr := rollback(); rollbackErr != nil {
		// The claim could not be withdrawn, so report that instead of the conflict:
		// the storage is left pointing at another project's token and the failure
		// needs an operator, not a retry.
		return rollbackErr
	}

	return conflictErr
}

func (s *SecretStorageServiceImpl) Create(storage db.SecretStorage) (res db.SecretStorage, err error) {
	sourceStorageType := storage.SourceStorageType
	sourceStorageKey := ""

	if storage.Secret == "" {
		err = common_errors.NewUserErrorS("secret must be set")
		return
	}

	if sourceStorageType != nil {
		sourceStorageKey, err = s.resolveSourceStorageKey(*sourceStorageType, storage.Secret, storage.ProjectID)
		if err != nil {
			return
		}
	}

	res, err = s.secretStorageRepo.CreateSecretStorage(storage)

	if err != nil {
		return
	}

	key := db.AccessKey{
		Name:              random.String(10),
		Type:              db.AccessKeyString,
		ProjectID:         &storage.ProjectID,
		Owner:             db.AccessKeySecretStorage,
		StorageID:         &res.ID,
		SourceStorageType: sourceStorageType,
	}

	if sourceStorageKey != "" {
		key.SourceStorageKey = &sourceStorageKey
	} else {
		key.String = storage.Secret
	}

	if _, err = s.accessKeyService.Create(key); err != nil {
		return
	}

	err = s.confirmSourceStorageKeyClaim(sourceStorageType, sourceStorageKey, storage.ProjectID, func() error {
		return s.Delete(storage.ProjectID, res.ID)
	})

	return
}

func (s *SecretStorageServiceImpl) Update(storage db.SecretStorage) (err error) {
	keys, err := s.accessKeyService.GetAll(storage.ProjectID, db.GetAccessKeyOptions{
		Owner:     db.AccessKeySecretStorage,
		StorageID: &storage.ID,
	}, db.RetrieveQueryParams{})

	if err != nil {
		return
	}

	sourceStorageType := storage.SourceStorageType
	sourceStorageKey := ""

	// Validated before anything is written: an existing storage must not be able to
	// be re-pointed at a token belonging to another project, and a rejected update
	// must leave the storage row exactly as it was.
	if sourceStorageType != nil && storage.Secret != "" {
		sourceStorageKey, err = s.resolveSourceStorageKey(*sourceStorageType, storage.Secret, storage.ProjectID)
		if err != nil {
			return
		}
	}

	err = s.secretStorageRepo.UpdateSecretStorage(storage)
	if err != nil {
		return
	}

	if storage.Secret == "" {
		// An empty vault token means the user didn't set a new one, so the existing
		// access key — if there is one — keeps the token it already holds.
		return
	}

	if len(keys) == 0 {
		newKey := db.AccessKey{
			Name:              random.String(10),
			Type:              db.AccessKeyString,
			ProjectID:         &storage.ProjectID,
			Owner:             db.AccessKeySecretStorage,
			StorageID:         &storage.ID,
			SourceStorageType: sourceStorageType,
		}

		if sourceStorageKey != "" {
			newKey.SourceStorageKey = &sourceStorageKey
		} else {
			newKey.String = storage.Secret
		}

		var created db.AccessKey
		created, err = s.accessKeyService.Create(newKey)
		if err != nil {
			return
		}

		err = s.confirmSourceStorageKeyClaim(sourceStorageType, sourceStorageKey, storage.ProjectID, func() error {
			return s.accessKeyService.Delete(storage.ProjectID, created.ID)
		})

		return
	}

	vault := keys[0]

	vault.OverrideSecret = true
	vault.SourceStorageType = sourceStorageType
	if sourceStorageKey != "" {
		vault.SourceStorageKey = &sourceStorageKey
		vault.String = ""
		// Clear previously persisted encrypted secret when switching to env/file source.
		vault.Secret = nil
	} else {
		vault.SourceStorageKey = nil
		vault.String = storage.Secret
	}

	if err = s.accessKeyService.Update(vault); err != nil {
		return
	}

	err = s.confirmSourceStorageKeyClaim(sourceStorageType, sourceStorageKey, storage.ProjectID, func() error {
		// Written back through the repository rather than the service so the row is
		// restored exactly as it was read: the service would re-encrypt from a
		// plaintext this copy no longer carries and lose the stored ciphertext.
		previous := keys[0]
		previous.OverrideSecret = true
		return s.accessKeyRepo.UpdateAccessKey(previous)
	})

	return
}

func (s *SecretStorageServiceImpl) GetSecretStorages(projectID int) (storages []db.SecretStorage, err error) {
	return pro.GetSecretStorages(s.secretStorageRepo, projectID)
}
