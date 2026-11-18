package cli

import (
	"context"
	"encoding/json"
	"fmt"

	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/manifest/parser"
)

// configMapDataReader is the slice of the cluster client that reads a
// ConfigMap whole: its data, and the resourceVersion a write at what was
// read is compared with. run reads the egress policy through it (ADR 0023
// M2.6d, A23-47, A28-10), and a plan the key pin (pinPlanReader).
type configMapDataReader interface {
	ConfigMapData(ctx context.Context, namespace, name string) (map[string]string, string, bool, error)
}

// credentialMinter gives namespace/app its egress credential: a fresh one
// when a run deploys (mintEgressCredential), and a placeholder in a plan,
// which mints nothing (ADR 0023 M2.6d, A23-30, A23-47).
type credentialMinter func(namespace, app string) (string, error)

// mintEgressCredential is the credentialMinter of a run that deploys: a new
// random credential for every application, whatever its name.
func mintEgressCredential(string, string) (string, error) {
	return policy.NewCredential()
}

// egressPolicy returns the instance's whole policy, existing as it was read
// (readEgressPolicyAt), with this deployment's applications in it, each with
// the credential mint gives it: the document, and the credentials by
// application.
//
// The merge is the point, and it is a lesson this project has already paid for
// once: one FatLine serves every application on an instance, so a `farcast run`
// that wrote only its own deployment's applications would silently revoke every
// other deployment's egress. That is the same shape as the metering the 4.2
// walk found a redeploy erasing, arrived at from a different direction.
//
// The cluster's own ConfigMap is the source of truth rather than local state,
// because an instance may be deployed to from more than one machine and the
// second machine has never heard of the first one's applications. So the
// read, the comparison of what was read under --confirm, and this, which
// mints, are three steps (A28-10): nothing is minted before the policy read
// is known to be the one a plan was made over.
func egressPolicy(existing *policy.Document, namespace string, m parser.Manifest, mint credentialMinter) (*policy.Document, map[string]string, error) {
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
		credential, err := mint(namespace, app.Name)
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
//
// world reads it so. run reads it with its resourceVersion
// (readEgressPolicyAt), to the same three outcomes.
func readEgressPolicy(ctx context.Context, cl configMapReader) (*policy.Document, error) {
	raw, found, err := cl.ConfigMapValue(ctx, fldeploy.DefaultNamespace, fldeploy.PolicyConfigMap, fldeploy.PolicyKey)
	if err != nil {
		if !found {
			return nil, fmt.Errorf("read the instance's egress policy: %w", err)
		}
		// Present but missing its key — the same hazard as an unparseable one,
		// and the same kind: the cluster holds a document that does not read.
		return nil, policyWithoutItsKey()
	}
	if !found {
		return &policy.Document{Version: policy.Version}, nil
	}
	return parseEgressPolicy(raw)
}

// readEgressPolicyAt is readEgressPolicy for run, with the ConfigMap's
// resourceVersion, which a plan binds on the policy's write and --confirm
// compares before it mints (ADR 0023 M2.6d, A23-47, A28-10). Its outcomes
// are readEgressPolicy's: no ConfigMap is an empty document, at no
// resourceVersion; one without policy.json is document_unreadable; one
// whose policy.json does not parse is as readEgressPolicy has it.
func readEgressPolicyAt(ctx context.Context, cl configMapDataReader) (*policy.Document, string, error) {
	data, rv, found, err := cl.ConfigMapData(ctx, fldeploy.DefaultNamespace, fldeploy.PolicyConfigMap)
	if err != nil {
		return nil, "", fmt.Errorf("read the instance's egress policy: %w", err)
	}
	if !found {
		return &policy.Document{Version: policy.Version}, "", nil
	}
	raw, ok := data[fldeploy.PolicyKey]
	if !ok {
		return nil, "", policyWithoutItsKey()
	}
	doc, err := parseEgressPolicy(raw)
	if err != nil {
		return nil, "", err
	}
	return doc, rv, nil
}

// policyWithoutItsKey is the refusal of a policy ConfigMap that is there
// without policy.json: the same hazard as one that does not parse, and the
// same kind, since the cluster holds a document that does not read.
func policyWithoutItsKey() error {
	return withKind(kindDocumentUnreadable, fmt.Errorf("the egress policy in %s/%s has no %q; refusing to replace it, because "+
		"rewriting it from scratch would revoke every application already running",
		fldeploy.DefaultNamespace, fldeploy.PolicyConfigMap, fldeploy.PolicyKey))
}

// parseEgressPolicy is the policy document raw, policy.json's value as read,
// or the refusal to replace one that does not parse.
func parseEgressPolicy(raw string) (*policy.Document, error) {
	doc, err := policy.Parse([]byte(raw))
	if err != nil {
		err = fmt.Errorf("the instance's existing egress policy could not be read (%w); refusing to replace "+
			"it, because rewriting it from scratch would revoke every application already running", err)
		// A document of another version is version skew — one side is older
		// than the other — and is marked so a reader can tell it from one that
		// is broken. The words are the same either way.
		var head struct {
			Version *int `json:"version"`
		}
		if json.Unmarshal([]byte(raw), &head) == nil && head.Version != nil && *head.Version != policy.Version {
			return nil, withKind(kindVersionSkew, err)
		}
		return nil, withKind(kindDocumentUnreadable, err)
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
