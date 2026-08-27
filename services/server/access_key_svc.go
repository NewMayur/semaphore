package server

import (
	"errors"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/pkg/common_errors"
)

type AccessKeyService interface {
	Update(key db.AccessKey) error
	Create(key db.AccessKey) (newKey db.AccessKey, err error)
	GetAll(projectID int, options db.GetAccessKeyOptions, params db.RetrieveQueryParams) ([]db.AccessKey, error)
	Delete(projectID int, keyID int) (err error)
}

type AccessKeyServiceImpl struct {
	accessKeyRepo     db.AccessKeyManager
	encryptionService AccessKeyEncryptionService
	secretStorageRepo db.SecretStorageRepository
}

func NewAccessKeyService(
	accessKeyRepo db.AccessKeyManager,
	encryptionService AccessKeyEncryptionService,
	secretStorageRepo db.SecretStorageRepository,
) AccessKeyService {
	return &AccessKeyServiceImpl{
		accessKeyRepo:     accessKeyRepo,
		encryptionService: encryptionService,
		secretStorageRepo: secretStorageRepo,
	}
}

func (s *AccessKeyServiceImpl) Delete(projectID int, keyID int) (err error) {
	key, err := s.accessKeyRepo.GetAccessKey(projectID, keyID)
	if err != nil {
		return
	}

	if key.SourceStorageID != nil {
		var storage db.SecretStorage
		storage, err = s.secretStorageRepo.GetSecretStorage(projectID, *key.SourceStorageID)
		if err != nil {
			return
		}

		if storage.ReadOnly || key.Synchronized {
			// Do nothing

			//if key.Synchronized {
			//	err = common_errors.NewUserErrorS("cannot delete synchronized secret from read-only storage")
			//}
		} else {
			err = s.encryptionService.DeleteSecret(&key)
		}

		if err != nil {
			return
		}
	}

	err = s.accessKeyRepo.DeleteAccessKey(projectID, keyID)

	return
}

func (s *AccessKeyServiceImpl) GetAll(projectID int, options db.GetAccessKeyOptions, params db.RetrieveQueryParams) ([]db.AccessKey, error) {
	return s.accessKeyRepo.GetAccessKeys(projectID, options, params)
}

// claimSourceStorageKey canonicalizes the external source a key reads its value from
// and refuses it when another project already reads from the same place.
//
// A file path or an environment variable name is not scoped to a project: every key
// naming it reads the same bytes. Letting a second project name a source a first one
// already uses hands it that project's secret — and for a secret storage token, every
// secret that token unlocks. This is the choke point for that rule, so it holds for
// the secret storage service, the project key endpoints and environment secrets
// alike; validating in any one caller would leave the others open.
//
// The canonical form is written back into key so that the row persisted downstream
// cannot be matched by spelling the same path differently later.
func (s *AccessKeyServiceImpl) claimSourceStorageKey(key *db.AccessKey) error {
	if key.SourceStorageType == nil || key.SourceStorageKey == nil {
		return nil
	}

	if !db.IsExternalSourceStorageType(*key.SourceStorageType) {
		return nil
	}

	canonical, err := db.ValidateSourceStorageKey(*key.SourceStorageType, *key.SourceStorageKey)
	if err != nil {
		return err
	}

	existing, err := s.accessKeyRepo.GetAccessKeysBySourceStorageType(*key.SourceStorageType)
	if err != nil {
		return err
	}

	if db.FindConflictingSourceStorageKey(
		existing, *key.SourceStorageType, canonical, key.ProjectID, key.ID) != nil {
		return db.ErrSourceStorageKeyClaimed
	}

	key.SourceStorageKey = &canonical

	return nil
}

func (s *AccessKeyServiceImpl) Create(key db.AccessKey) (newKey db.AccessKey, err error) {

	if err = s.claimSourceStorageKey(&key); err != nil {
		return
	}

	// SerializeSecret encrypts/persists the secret for writable backends. For read-only
	// external storage the secret is not stored in Semaphore, so SerializeSecret fails
	// with ErrReadOnlyStorage; we still create the access key row (metadata / reference).
	err = s.encryptionService.SerializeSecret(&key)
	if err != nil && !errors.Is(err, ErrReadOnlyStorage) {
		return
	}

	newKey, err = s.accessKeyRepo.CreateAccessKey(key)
	return
}

func (s *AccessKeyServiceImpl) Update(key db.AccessKey) (err error) {
	if !key.OverrideSecret {
		// UpdateAccessKey writes the source storage columns only when the secret is
		// overridden, so there is no new claim to validate on this path.
		err = s.accessKeyRepo.UpdateAccessKey(key)
		return
	}

	if err = s.claimSourceStorageKey(&key); err != nil {
		return
	}

	var oldKey db.AccessKey
	oldKey, err = s.accessKeyRepo.GetAccessKey(*key.ProjectID, key.ID)
	if err != nil {
		return
	}

	if oldKey.SourceStorageType != nil && !oldKey.IsNativelyReadOnly() {
		// validate if it is secure to override secret storage

		var oldSt db.SecretStorage
		oldSt, err = s.secretStorageRepo.GetSecretStorage(*key.ProjectID, *oldKey.SourceStorageID)
		if err != nil {
			return
		}

		if !oldSt.ReadOnly && (key.SourceStorageID == nil || *oldKey.SourceStorageID != *key.SourceStorageID) {
			err = common_errors.NewUserErrorS("cannot override secret storage")
			return
		}
	}

	if !key.IsNativelyReadOnly() {
		err = s.encryptionService.SerializeSecret(&key)
		if err != nil {
			return
		}
	}

	err = s.accessKeyRepo.UpdateAccessKey(key)

	return
}
