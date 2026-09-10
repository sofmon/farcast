package farcast

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// envSecretsPrefix is the key subtree this application's secrets live under,
// fully qualified, ending in "/". The platform sets it; the SDK never derives
// it.
//
// Deriving it would mean guessing — from the scope name, from the application
// name — and a guess that lands one segment away addresses somebody else's
// subtree, or a subtree the keyholder does not protect. The platform knows the
// answer exactly (Planck renders it from the recorded scope prefix), so it
// says it.
const envSecretsPrefix = "FARCAST_SECRETS_PREFIX"

// SecretsSegment is the reserved path segment that marks the secrets subtree
// inside a scope: <scope prefix>/secrets/<app>/<name>.
//
// It is a contract between three parties that cannot import each other — this
// module has no dependencies, DataSphere is in the root module, and the CLI
// writes what both read — so, like the wire codes, it is duplicated
// deliberately and frozen. DataSphere mirrors it as datasphere.SecretsSegment
// and refuses application writes under it; `farcast secret` writes there and
// nowhere else.
const SecretsSegment = "secrets"

// newSecretsFromEnv builds the capability from the environment.
//
// Three outcomes, kept distinct for the same reason storage keeps them: no
// prefix means this build has no secrets wired (the stub); a prefix that
// cannot be used means something is misconfigured (secretsBroken); otherwise a
// live reader over the storage capability.
func newSecretsFromEnv() SecretsAPI {
	prefix := strings.TrimSpace(os.Getenv(envSecretsPrefix))
	if prefix == "" {
		return secretsStub{}
	}
	if err := validSecretsPrefix(prefix); err != nil {
		return secretsBroken{err: err}
	}
	store := Storage()
	if _, unwired := store.(storageStub); unwired {
		// Secrets are objects in the instance's encrypted storage, served by
		// the same keyholder. Saying "not implemented" here would send an
		// operator to the SDK's roadmap when the actual fault is one missing
		// variable in the workload they just deployed.
		return secretsBroken{err: fmt.Errorf(
			"%w: secrets are served by the keyholder, and %s is not set",
			ErrStorageUnavailable, envStorageEndpoint)}
	}
	return &secretsClient{prefix: prefix, store: store}
}

// validSecretsPrefix checks the prefix names the secrets subtree.
//
// The reserved segment is REQUIRED, not merely conventional. It is what the
// keyholder keys its write refusal on, so a prefix without it points this
// capability at ordinary storage — where any application may create and
// overwrite objects — while still calling itself Secrets. A mis-rendered
// ConfigMap must not be able to make that swap quietly.
func validSecretsPrefix(prefix string) error {
	switch {
	case !strings.HasSuffix(prefix, "/"):
		return fmt.Errorf("%w: %s must end in %q", ErrStorageUnavailable, envSecretsPrefix, "/")
	case strings.Contains(prefix, "//"), strings.Contains(prefix, ".."):
		return fmt.Errorf("%w: %s is not a well-formed key prefix", ErrStorageUnavailable, envSecretsPrefix)
	case !strings.Contains(prefix, "/"+SecretsSegment+"/"):
		return fmt.Errorf("%w: %s does not name the %q subtree, so it is not a secrets prefix",
			ErrStorageUnavailable, envSecretsPrefix, SecretsSegment)
	}
	return nil
}

// secretsClient reads secrets as objects through the storage capability.
//
// It holds the StorageAPI rather than its own HTTP client so the two can never
// disagree about where the keyholder is, which CA verifies it, or which scope
// this application declares — one environment, one client, one answer.
type secretsClient struct {
	prefix string
	store  StorageAPI
}

var _ SecretsAPI = (*secretsClient)(nil)

// secretsBroken is configured-but-unusable, distinct from both the stub and a
// seal for the reasons storageBroken records.
type secretsBroken struct{ err error }

var _ SecretsAPI = secretsBroken{}

func (s secretsBroken) Get(context.Context, string) (Secret, error) { return Secret{}, s.err }

func (c *secretsClient) Get(ctx context.Context, name string) (Secret, error) {
	if !validSecretName(name) {
		// Local, and before any call: a name with a separator in it would
		// address a subtree this application was not given, and asking the
		// keyholder to refuse it is a worse answer than not asking.
		return Secret{}, fmt.Errorf(
			"farcast: %q is not a valid secret name (letters, digits, '_', '-' and '.', up to %d bytes, no path separators)",
			name, MaxSecretNameLen)
	}
	data, err := c.store.Read(ctx, c.prefix+name)
	if err != nil {
		if errors.Is(err, ErrObjectNotFound) {
			// The substrate's vocabulary stops here. An application asked for
			// a secret and there is none; that it is stored as an object is
			// this SDK's business, and a capability that leaks its backing
			// store's sentinels cannot change that store later.
			return Secret{}, fmt.Errorf("farcast: secret %q: %w", name, ErrSecretNotFound)
		}
		return Secret{}, fmt.Errorf("farcast: secret %q: %w", name, err)
	}
	return Secret{value: string(data)}, nil
}
