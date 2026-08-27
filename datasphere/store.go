package datasphere

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/sofmon/farcast/datasphere/internal/crypto"
)

// MetaName is the provider-metadata key under which every object carries the
// base64 of its sealed logical name. It is a mirror of the authoritative copy
// in the blob header, and it exists for one reason: it makes Store.List cost
// one list call per page instead of one full object fetch per name.
const MetaName = "farcast-name"

// Store is the encrypting layer over a Provider — and the layering rule of
// this whole module: Store is the only code in FarCast that holds storage
// plaintext or logical object names together with the ability to reach a
// cloud. Everything below it operates on ciphertext and opaque tokens, which
// is why "the cloud provider sees only encrypted blobs" is a structural fact
// rather than a promise each adapter has to keep.
//
// Its four methods are the shape of sdk/go's StorageAPI, so wiring the SDK to
// it (3.2) is transport rather than translation.
type Store struct {
	provider Provider
	bucket   string
	keys     Keyring

	// nameKey is the active name key's material and tokenKey the HMAC key
	// derived from it. Both are resolved once at construction: they are stable
	// for the life of a Store, and re-deriving per call would put an HKDF in
	// front of every object operation for nothing.
	nameKey  []byte
	tokenKey []byte
}

// NewStore wraps a Provider and a bucket with the instance's keyring. It is
// the only constructor; there is no unencrypted path, in code or in tooling.
//
// It deliberately does not talk to the cloud, so it takes no context. The
// composition root — the harness now, the CLI and the in-cluster service
// later — is what runs Provider.Validate against the recorded BucketRef before
// getting here, so that tampered local metadata cannot point writes at a
// stranger's bucket.
func NewStore(p Provider, bucket string, keys Keyring) (*Store, error) {
	if p == nil {
		return nil, errors.New("datasphere: a provider is required")
	}
	if bucket == "" {
		return nil, errors.New("datasphere: a bucket name is required")
	}
	if err := keys.Valid(); err != nil {
		return nil, err
	}
	nameKey, err := keys.ActiveNameKey()
	if err != nil {
		return nil, err
	}
	tokenKey, err := crypto.NameTokenKey(nameKey.key)
	if err != nil {
		return nil, fmt.Errorf("datasphere: derive name token key: %w", err)
	}
	return &Store{
		provider: p,
		bucket:   bucket,
		keys:     keys,
		nameKey:  nameKey.key,
		tokenKey: tokenKey,
	}, nil
}

// Read returns the plaintext stored under key, or an error. Never both, and
// never partial output: a blob that fails authentication anywhere yields
// ErrIntegrity with nothing attached.
func (s *Store) Read(ctx context.Context, key string) ([]byte, error) {
	stored, err := s.StoredName(key)
	if err != nil {
		return nil, err
	}
	obj, err := s.provider.Get(ctx, s.bucket, stored)
	if err != nil {
		return nil, err
	}
	return crypto.Open(s.keys.lookup(), key, obj.Data)
}

// Write stores data under key, encrypting it under a fresh single-use data key
// wrapped by the keyring's active key-encryption key.
//
// It is an upsert: writing an existing key atomically replaces it, object and
// metadata together, on the Provider contract's atomicity. Lost-update
// protection — generations, preconditions, compare-and-swap — is out of
// scope here; if a multi-writer reality demands it, it arrives as an interface
// addition, not as a reinterpretation of this method.
func (s *Store) Write(ctx context.Context, key string, data []byte) error {
	stored, err := s.StoredName(key)
	if err != nil {
		return err
	}
	kek, err := s.keys.ActiveKEK()
	if err != nil {
		return err
	}
	blob, sealedName, err := crypto.Seal(
		crypto.Key{ID: kek.ID.raw(), Material: kek.key},
		s.nameKey, stored, key, data, rand.Reader,
	)
	if err != nil {
		return err
	}
	return s.provider.Put(ctx, s.bucket, Object{
		Name: stored,
		Data: blob,
		Meta: map[string]string{MetaName: base64.StdEncoding.EncodeToString(sealedName)},
	})
}

// Delete removes the object stored under key. Deleting an absent key is not an
// error.
func (s *Store) Delete(ctx context.Context, key string) error {
	stored, err := s.StoredName(key)
	if err != nil {
		return err
	}
	return s.provider.Delete(ctx, s.bucket, stored)
}

// List returns the logical keys under prefix, sorted.
//
// The cloud-side listing narrows to the longest /-aligned portion of the
// prefix — a token is an HMAC of a whole segment, so a partial one cannot be
// tokenized — and the recovered logical names are then filtered against the
// full prefix here. Arbitrary string prefixes are honoured exactly, at the
// honest cost of over-listing within one segment.
//
// Names come from each object's metadata mirror. An object whose mirror is
// missing or does not authenticate falls back to a full fetch of that object,
// whose header carries the authoritative copy — degraded, never silently
// wrong. An object that fails even there is reported in a joined error
// alongside the names that did resolve: the caller sees what could be read and
// is told, loudly, what could not.
func (s *Store) List(ctx context.Context, prefix string) ([]string, error) {
	infos, err := s.provider.List(ctx, s.bucket, crypto.TokenPrefix(s.tokenKey, prefix))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(infos))
	var failures []error
	for _, info := range infos {
		name, err := s.logicalName(ctx, info)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, errors.Join(failures...)
}

// StoredName returns the opaque path a logical key is stored under.
//
// It is the module's transparency surface: `datasphere ls --tokens` prints it
// so an operator can hold the stored name next to the logical one and see for
// themselves that the cloud holds neither the name nor the data.
func (s *Store) StoredName(key string) (string, error) {
	if err := crypto.ValidateLogicalKey(key); err != nil {
		return "", err
	}
	return crypto.TokenPath(s.tokenKey, key), nil
}

// Bucket is the bucket this Store writes to.
func (s *Store) Bucket() string { return s.bucket }

// logicalName recovers one listing entry's logical name, preferring the
// metadata mirror and falling back to the object's authoritative header.
func (s *Store) logicalName(ctx context.Context, info ObjectInfo) (string, error) {
	if mirror := info.Meta[MetaName]; mirror != "" {
		if sealed, err := base64.StdEncoding.DecodeString(mirror); err == nil {
			if name, err := crypto.OpenName(s.nameKey, info.Name, sealed); err == nil {
				return name, nil
			}
		}
	}
	obj, err := s.provider.Get(ctx, s.bucket, info.Name)
	if err != nil {
		return "", fmt.Errorf("datasphere: recover name of stored object %s: %w", info.Name, err)
	}
	name, err := crypto.HeaderName(s.nameKey, info.Name, obj.Data)
	if err != nil {
		return "", fmt.Errorf("datasphere: recover name of stored object %s: %w", info.Name, err)
	}
	return name, nil
}
