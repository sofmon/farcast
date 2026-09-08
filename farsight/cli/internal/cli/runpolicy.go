package cli

import (
	"context"
	"fmt"

	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/manifest/parser"
)

// policyReader is the slice of the cluster client the egress policy needs.
type policyReader interface {
	ConfigMapValue(ctx context.Context, namespace, name, key string) (string, bool, error)
}

// egressPolicy mints this deployment's credentials and returns the instance's
// whole policy with them merged in.
//
// The merge is the point, and it is a lesson this project has already paid for
// once: one FatLine serves every application on an instance, so a `farcast run`
// that wrote only its own deployment's applications would silently revoke every
// other deployment's egress. That is the same shape as the metering the 4.2
// walk found a redeploy erasing, arrived at from a different direction.
//
// The cluster's own ConfigMap is the source of truth rather than local state,
// because an instance may be deployed to from more than one machine and the
// second machine has never heard of the first one's applications.
func egressPolicy(ctx context.Context, cl policyReader, namespace string, m parser.Manifest) (*policy.Document, map[string]string, error) {
	existing, err := readEgressPolicy(ctx, cl)
	if err != nil {
		return nil, nil, err
	}

	// This deployment is being replaced, so its previous applications go —
	// including any the manifest no longer declares. An application removed
	// from a manifest must stop being allowed anything.
	doc := &policy.Document{Version: policy.Version}
	for _, app := range existing.Apps {
		if app.Namespace != namespace {
			doc.Apps = append(doc.Apps, app)
		}
	}

	credentials := make(map[string]string, len(m.Apps))
	for _, app := range m.Apps {
		credential, err := policy.NewCredential()
		if err != nil {
			return nil, nil, err
		}
		credentials[app.Name] = credential
		doc.Apps = append(doc.Apps, policy.App{
			Name:             app.Name,
			Namespace:        namespace,
			CredentialSHA256: policy.HashCredential(credential),
			External:         app.External,
		})
	}
	return doc, credentials, nil
}

// readEgressPolicy reads the instance's current policy.
//
// A missing ConfigMap is an instance that has never deployed an application,
// which is not an error. A ConfigMap that will not parse IS one: continuing
// from an empty document would silently revoke every application already
// running, and "I could not read the policy" is a far better outcome than
// "your applications stopped reaching anything and nothing said why".
func readEgressPolicy(ctx context.Context, cl policyReader) (*policy.Document, error) {
	raw, found, err := cl.ConfigMapValue(ctx, fldeploy.DefaultNamespace, fldeploy.PolicyConfigMap, fldeploy.PolicyKey)
	if err != nil {
		if !found {
			return nil, fmt.Errorf("read the instance's egress policy: %w", err)
		}
		// Present but missing its key — the same hazard as an unparseable one.
		return nil, fmt.Errorf("the egress policy in %s/%s has no %q; refusing to replace it, because "+
			"rewriting it from scratch would revoke every application already running",
			fldeploy.DefaultNamespace, fldeploy.PolicyConfigMap, fldeploy.PolicyKey)
	}
	if !found {
		return &policy.Document{Version: policy.Version}, nil
	}
	doc, err := policy.Parse([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("the instance's existing egress policy could not be read (%w); refusing to replace "+
			"it, because rewriting it from scratch would revoke every application already running", err)
	}
	return doc, nil
}

// egressSummary is what the result reports about the policy that was written.
type egressSummary struct {
	Applications int `json:"applications"`
	Hosts        int `json:"hosts"`
	Others       int `json:"other_deployments,omitempty"`
}

func summarise(doc *policy.Document, namespace string) egressSummary {
	var s egressSummary
	for _, app := range doc.Apps {
		if app.Namespace == namespace {
			s.Applications++
			s.Hosts += len(app.External)
			continue
		}
		s.Others++
	}
	return s
}
