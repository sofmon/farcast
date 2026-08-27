// Package storage resolves an instance into usable DataSphere storage: the
// cloud provider from the recorded credentials, the bucket from the recorded
// name, and the encrypting Store from the local keyring.
//
// It exists as its own package because the order of those steps is a safety
// property rather than plumbing. The bucket's name is recorded before it is
// created, the recorded bucket is validated before a Store can write through
// it, and the keyring is never created by accident. Spreading that across the
// command implementations would make it four opportunities to get wrong
// instead of one place to get right.
package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sofmon/farcast/datasphere"
	_ "github.com/sofmon/farcast/datasphere/providers" // register cloud adapters (gcs)
	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// maxMintAttempts bounds the mint/record/retry loop. A collision in a
// 32-bit random suffix is already improbable; three of them in a row is a
// signal to stop and let a human look, not to keep minting.
const maxMintAttempts = 3

// storageProviders maps a compute provider to the storage provider that
// belongs with it. It is a table rather than a derivation so that adding a
// cloud is one line and so an instance's recorded choice can be compared
// against it.
var storageProviders = map[string]string{"gke": "gcs"}

// Session is an instance's storage, resolved and ready.
type Session struct {
	Instance string
	Bucket   string
	Location string

	Provider datasphere.Provider
	// Store is nil when the session was opened without a keyring.
	Store   *datasphere.Store
	Keyring datasphere.Keyring

	// Notices are things that did not fail the call but that the operator must
	// be told — a forced retention window, a freshly created bucket and its
	// price model.
	Notices []string
	// KeyringMinted and BucketCreated report what this call brought into
	// existence, so a caller can say so exactly once.
	KeyringMinted bool
	BucketCreated bool
}

// Options controls how much an Open is allowed to bring into existence.
type Options struct {
	Dir      config.Dir
	Instance string

	// WithoutKeyring resolves the provider and the bucket but builds no Store.
	//
	// This is what `release`'s teardown gate and a totals-only usage report
	// use, and it is not a convenience: an operator who has lost keys.yaml can
	// no longer read a byte of their data, but they can still be billed for
	// it, and they must still be able to see that and stop it.
	WithoutKeyring bool

	// Mint permits this call to create what is missing — the keyring, the
	// bucket, or both. Read-only commands leave it false so that a typo in an
	// instance name cannot quietly provision anything.
	Mint bool
}

// Open resolves an instance's storage.
func Open(ctx context.Context, opt Options) (*Session, error) {
	meta, err := opt.Dir.LoadInstanceMetadata(opt.Instance)
	if err != nil {
		return nil, fmt.Errorf("load instance %q: %w", opt.Instance, err)
	}
	creds, err := opt.Dir.LoadInstanceCredentials(opt.Instance)
	if err != nil {
		return nil, fmt.Errorf("load credentials for %q: %w", opt.Instance, err)
	}

	providerName, err := storageProviderFor(meta)
	if err != nil {
		return nil, err
	}
	provider, err := datasphere.Open(providerName, datasphere.Config{
		Credentials: []byte(creds.ServiceAccountKey),
		Project:     meta.Project,
		Location:    meta.Region,
	})
	if err != nil {
		return nil, err
	}

	session := &Session{Instance: opt.Instance, Location: meta.Region, Provider: provider}
	if err := ensureBucket(ctx, opt, meta, provider, providerName, session); err != nil {
		return nil, err
	}

	// The enforcement point, and the reason it is here rather than in each
	// command: the recorded bucket is proved to be this instance's before any
	// Store exists to write through it, so tampered local metadata cannot
	// point writes at a stranger's bucket.
	ref := datasphere.BucketRef{Name: session.Bucket, Location: session.Location, Instance: opt.Instance}
	if err := provider.Validate(ctx, ref); err != nil {
		return nil, fmt.Errorf("the recorded storage bucket for %q did not validate: %w", opt.Instance, err)
	}

	if opt.WithoutKeyring {
		return session, nil
	}
	if err := openKeyring(opt, session); err != nil {
		return nil, err
	}
	store, err := datasphere.NewStore(provider, session.Bucket, session.Keyring)
	if err != nil {
		return nil, err
	}
	session.Store = store
	return session, nil
}

// storageProviderFor picks the storage provider for an instance, preferring
// what was recorded so a change to the table below cannot repoint an existing
// instance at a different cloud.
func storageProviderFor(meta *config.InstanceMetadata) (string, error) {
	if meta.Storage != nil && meta.Storage.Provider != "" {
		return meta.Storage.Provider, nil
	}
	name, ok := storageProviders[meta.Provider]
	if !ok {
		return "", fmt.Errorf("no storage provider is known for compute provider %q", meta.Provider)
	}
	return name, nil
}

// ensureBucket records a bucket name before creating it, and converges a name
// conflict by minting another — but only while the record is still just an
// intent.
func ensureBucket(ctx context.Context, opt Options, meta *config.InstanceMetadata, provider datasphere.Provider, providerName string, session *Session) error {
	if meta.Storage == nil {
		if !opt.Mint {
			return fmt.Errorf("instance %q has no storage yet; a command that writes will create it", opt.Instance)
		}
		if err := mintAndRecord(opt, meta, providerName); err != nil {
			return err
		}
	}
	session.Bucket = meta.Storage.Bucket
	if meta.Storage.Location != "" {
		session.Location = meta.Storage.Location
	}

	// A command that was not permitted to create anything does not get to
	// create a bucket, whatever the record says — including when the record
	// shows an earlier attempt that never finished. A typo in an instance name
	// must not be able to quietly provision one, and a read-only command
	// against a bucket that does not exist should say so at the ownership
	// check rather than bring it into being.
	//
	// A write command re-ensures even when the bucket is known to exist. That
	// is the defensive ensure the module specifies: it is what converges an
	// instance created before it had storage, and it is where an ownership
	// refusal on a recorded bucket surfaces.
	if !opt.Mint {
		return nil
	}

	for attempt := 1; ; attempt++ {
		bucket, err := provider.EnsureBucket(ctx, datasphere.BucketSpec{
			Name:     meta.Storage.Bucket,
			Instance: opt.Instance,
			Location: session.Location,
		})
		switch {
		case err == nil || errors.Is(err, datasphere.ErrRetentionForced):
			if err != nil {
				session.Notices = append(session.Notices, err.Error())
			}
			if meta.Storage.CreatedAt.IsZero() {
				session.BucketCreated = true
				meta.Storage.CreatedAt = time.Now().UTC().Truncate(time.Second)
				if saveErr := opt.Dir.SaveInstanceMetadata(opt.Instance, meta); saveErr != nil {
					return fmt.Errorf("record the storage bucket for %q: %w", opt.Instance, saveErr)
				}
			}
			session.Bucket = bucket.Ref.Name
			return nil

		case errors.Is(err, datasphere.ErrNotOwned):
			// The distinction this branch turns on. While CreatedAt is empty
			// the recorded name is only an intent, so a global-namespace
			// collision is resolved by minting another. Once it is set, the
			// name has held real data — minting past the refusal would abandon
			// that data under a name nothing points at any more, which is a
			// far worse outcome than stopping.
			if !meta.Storage.CreatedAt.IsZero() {
				return fmt.Errorf("the recorded storage bucket %q for instance %q is refusing this instance's ownership (%w).\n"+
					"This bucket has held data, so FarCast will not mint a replacement and leave it behind. Inspect it in the cloud console before doing anything else",
					meta.Storage.Bucket, opt.Instance, err)
			}
			if !opt.Mint || attempt >= maxMintAttempts {
				return fmt.Errorf("could not claim a storage bucket name for %q after %d attempts: %w", opt.Instance, attempt, err)
			}
			if err := mintAndRecord(opt, meta, providerName); err != nil {
				return err
			}
			session.Bucket = meta.Storage.Bucket

		default:
			// Every other failure keeps the record, so a re-run converges.
			return fmt.Errorf("ensure storage for %q: %w", opt.Instance, err)
		}
	}
}

// mintAndRecord writes a freshly minted bucket name into local state BEFORE
// anything creates it. The suffix exists nowhere else, so a bucket created
// without this record would be billable storage nobody is watching under a
// name nobody can reconstruct.
func mintAndRecord(opt Options, meta *config.InstanceMetadata, providerName string) error {
	name, err := datasphere.MintBucketName(opt.Instance)
	if err != nil {
		return err
	}
	meta.Storage = &config.Storage{
		Bucket:     name,
		Location:   meta.Region,
		Provider:   providerName,
		RecordedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := opt.Dir.SaveInstanceMetadata(opt.Instance, meta); err != nil {
		return fmt.Errorf("record the storage bucket for %q: %w", opt.Instance, err)
	}
	return nil
}

// openKeyring loads the instance's keyring, minting one when permitted.
func openKeyring(opt Options, session *Session) error {
	exists, err := opt.Dir.InstanceKeyringExists(opt.Instance)
	if err != nil {
		return err
	}
	if !exists {
		if !opt.Mint {
			return fmt.Errorf("instance %q has no storage keyring yet; a command that writes will create it", opt.Instance)
		}
		keyring, err := datasphere.NewKeyring()
		if err != nil {
			return err
		}
		data, err := keyring.Marshal()
		if err != nil {
			return err
		}
		if err := opt.Dir.CreateInstanceKeyring(opt.Instance, data); err != nil {
			return fmt.Errorf("create the storage keyring for %q: %w", opt.Instance, err)
		}
		session.Keyring, session.KeyringMinted = keyring, true
		return nil
	}

	data, err := opt.Dir.LoadInstanceKeyring(opt.Instance)
	if err != nil {
		return fmt.Errorf("read the storage keyring for %q: %w\n%s", opt.Instance, err, datasphere.KeyLossWarning)
	}
	keyring, err := datasphere.ParseKeyring(data)
	if err != nil {
		return err
	}
	session.Keyring = keyring
	return nil
}
