package db

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/semaphoreui/semaphore/pkg/common_errors"
	"github.com/semaphoreui/semaphore/util"
)

// IsExternalSourceStorageType reports whether a key reads its value from a place
// outside Semaphore that is not itself scoped to a project: a file on disk or an
// environment variable. Every key naming such a source reads the same bytes, so
// those sources need cross-project ownership rules. Vault sources are addressed
// through SourceStorageID, which already belongs to a single project.
func IsExternalSourceStorageType(sourceStorageType AccessKeySourceStorageType) bool {
	switch sourceStorageType {
	case AccessKeySourceStorageFile, AccessKeySourceStorageEnv:
		return true
	default:
		return false
	}
}

// NormalizeSourceStorageKey rewrites the reference a key uses to locate its value
// into a canonical form, so that two references to the same source compare equal.
//
// For files the result is an absolute, lexically cleaned path: "/tmp/semaphore/token",
// "/tmp/semaphore//token", "/tmp/semaphore/./token" and "/tmp/semaphore/../semaphore/token"
// all collapse to "/tmp/semaphore/token". Storing the string as typed instead would
// let a caller defeat the cross-project uniqueness check by spelling the same path
// differently.
//
// Relative paths are rejected rather than resolved against the working directory:
// the nodes of an HA cluster need not share one, so the same input would canonicalize
// differently per node and the uniqueness check would not hold. The deserializer
// rejects them as well, see LocalAccessKeyDeserializer.deserialize.
func NormalizeSourceStorageKey(sourceStorageType AccessKeySourceStorageType, key string) (string, error) {
	switch sourceStorageType {
	case AccessKeySourceStorageEnv:
		name := strings.TrimSpace(key)
		if name == "" {
			return "", common_errors.NewUserErrorS("environment variable name must not be empty")
		}
		return name, nil

	case AccessKeySourceStorageFile:
		path := strings.TrimSpace(key)
		if path == "" {
			return "", common_errors.NewUserErrorS("file path must not be empty")
		}

		if !filepath.IsAbs(path) {
			return "", common_errors.NewUserErrorS("file path must be absolute")
		}

		// Abs implies Clean, which collapses "." and ".." segments. The path is
		// already absolute, so nothing is read from the process environment.
		return filepath.Abs(path)

	default:
		return "", common_errors.NewUserErrorS("unsupported source storage type")
	}
}

// ValidateSourceStorageKey normalizes a source reference and rejects a file path
// that points outside the configured secrets directory. That containment rule is
// the one the deserializer applies when it reads the value; applying it on write
// too means a path that could never be read is refused when it is configured
// rather than when a task later fails.
func ValidateSourceStorageKey(sourceStorageType AccessKeySourceStorageType, key string) (string, error) {
	normalized, err := NormalizeSourceStorageKey(sourceStorageType, key)
	if err != nil {
		return "", err
	}

	if sourceStorageType != AccessKeySourceStorageFile {
		return normalized, nil
	}

	// Skip containment when the secrets directory is not configured as an absolute
	// path: reads fail in that case regardless, and refusing every write would break
	// setups that never reach the deserializer. Dirs is a pointer and is nil until
	// the configuration is loaded.
	if util.Config == nil || util.Config.Dirs == nil {
		return normalized, nil
	}

	base := filepath.Clean(util.Config.Dirs.Secrets)
	if !filepath.IsAbs(base) {
		return normalized, nil
	}

	rel, err := filepath.Rel(base, normalized)
	if err != nil {
		return "", common_errors.NewUserError(err)
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", common_errors.NewUserErrorS("file path must be inside secrets path")
	}

	return normalized, nil
}

// SourceStorageKeysReferToSameToken reports whether a canonical source reference and
// one already stored resolve to the same secret.
//
// The stored side is normalized too, because rows written before this validation
// existed hold the string exactly as it was typed. A stored value that cannot be
// normalized is compared verbatim rather than skipped, so a malformed legacy row can
// never silently drop a conflict.
func SourceStorageKeysReferToSameToken(
	sourceStorageType AccessKeySourceStorageType,
	canonicalKey string,
	storedKey string,
) bool {
	if canonicalKey == storedKey {
		return true
	}

	if sourceStorageType != AccessKeySourceStorageFile {
		return false
	}

	storedPath := storedKey
	if normalized, err := NormalizeSourceStorageKey(sourceStorageType, storedKey); err == nil {
		storedPath = normalized
	}

	if canonicalKey == storedPath {
		return true
	}

	// Lexically distinct paths still reach the same file through a symlink or a hard
	// link, which Clean cannot see. Both files have to exist for os.Stat to answer;
	// when either is missing the comparison above is all there is to go on.
	canonicalInfo, err := os.Stat(canonicalKey)
	if err != nil {
		return false
	}

	storedInfo, err := os.Stat(storedPath)
	if err != nil {
		return false
	}

	return os.SameFile(canonicalInfo, storedInfo)
}

// FindConflictingSourceStorageKey returns the first key among keys that belongs to a
// different project than projectID and reads from the same file or environment
// variable as canonicalKey, or nil when the source is unclaimed.
//
// excludeKeyID skips the row being updated, which would otherwise conflict with
// itself. Pass 0 when creating.
func FindConflictingSourceStorageKey(
	keys []AccessKey,
	sourceStorageType AccessKeySourceStorageType,
	canonicalKey string,
	projectID *int,
	excludeKeyID int,
) *AccessKey {
	for i, other := range keys {
		if other.SourceStorageKey == nil {
			continue
		}

		if excludeKeyID != 0 && other.ID == excludeKeyID {
			continue
		}

		// Reuse inside one project stays within a single trust boundary, and two
		// storages of the same project sharing a token is a legitimate setup.
		if sameProject(projectID, other.ProjectID) {
			continue
		}

		if SourceStorageKeysReferToSameToken(sourceStorageType, canonicalKey, *other.SourceStorageKey) {
			return &keys[i]
		}
	}

	return nil
}

// sameProject treats two keys as belonging to one trust boundary only when both
// name the same project, or when neither belongs to a project at all.
func sameProject(a *int, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}

	return *a == *b
}

// ErrSourceStorageKeyClaimed is returned when a project tries to read its secret
// from a file or environment variable another project already reads from. It
// deliberately does not name the other project: the caller has no access to it and
// must not learn of it from this message.
var ErrSourceStorageKeyClaimed = common_errors.NewUserErrorS(
	"this secret source is already used by another project")
