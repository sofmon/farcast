package cli

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/manifest/parser"
)

// valueView is a ConfigMap reader's ConfigMapValue over another's
// ConfigMapData, answering as the cluster client does: a ConfigMap without
// the key is found, with an error.
type valueView struct{ cl configMapDataReader }

func (v valueView) ConfigMapValue(ctx context.Context, namespace, name, key string) (string, bool, error) {
	data, _, found, err := v.cl.ConfigMapData(ctx, namespace, name)
	if err != nil || !found {
		return "", found, err
	}
	value, ok := data[key]
	if !ok {
		return "", true, fmt.Errorf("ConfigMap %s/%s has no key %q", namespace, name, key)
	}
	return value, true, nil
}

// ADR 0023 M2.6d (A23-47, A28-10): run reads the egress policy whole, with
// the resourceVersion a plan binds and --confirm compares, and to the same
// outcomes as world's read (readEgressPolicy): no ConfigMap is an empty
// document at no resourceVersion; one without policy.json is
// document_unreadable; one that does not parse is document_unreadable, or
// version_skew for another version; a failed read is that failure.
func TestRunReadsTheEgressPolicyWithItsResourceVersion(t *testing.T) {
	ns, name, key := fldeploy.DefaultNamespace, fldeploy.PolicyConfigMap, fldeploy.PolicyKey
	running := &policy.Document{Version: policy.Version, Apps: []policy.App{{
		Name: "worker", Namespace: "other-deployment",
		CredentialSHA256: policy.HashCredential("their-credential"),
		External:         []parser.External{{Host: "queue.example", Reason: "jobs"}},
	}}}
	body, err := running.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("the API server said no")
	for _, row := range []struct {
		name    string
		data    map[string]string // by key, under the policy's ConfigMap
		readErr error
		rv      string
		doc     *policy.Document
		kind    string
		text    string
	}{
		{name: "no ConfigMap", doc: &policy.Document{Version: policy.Version}},
		{name: "a policy", data: map[string]string{key: string(body)}, rv: "41", doc: running},
		{name: "no policy.json", data: map[string]string{"other": "x"}, kind: kindDocumentUnreadable,
			text: fmt.Sprintf("the egress policy in %s/%s has no %q; refusing to replace it, because "+
				"rewriting it from scratch would revoke every application already running", ns, name, key)},
		{name: "a policy that does not parse", data: map[string]string{key: "{ not json"}, kind: kindDocumentUnreadable},
		{name: "another version", data: map[string]string{key: `{"version":2,"apps":[]}`}, kind: kindVersionSkew},
		{name: "a failed read", readErr: refused, kind: kindInternal,
			text: "read the instance's egress policy: the API server said no"},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFakeRun(twoAppManifest)
			f.configMaps = map[string]string{}
			for k, v := range row.data {
				f.configMaps[ns+"/"+name+"/"+k] = v
			}
			f.rvs = map[string]string{ns + "/" + name: row.rv}
			if row.readErr != nil {
				f.dataErrs = map[string]error{ns + "/" + name: row.readErr}
			}
			doc, rv, err := readEgressPolicyAt(t.Context(), f)
			if row.kind != "" {
				if err == nil || doc != nil || rv != "" || kindOf(classified(err)) != row.kind || (row.text != "" && err.Error() != row.text) {
					t.Fatalf("readEgressPolicyAt = %v, %q, %v (kind %s); want refused, kind %s, %q", doc, rv, err, kindOf(classified(err)), row.kind, row.text)
				}
				if row.readErr != nil && !errors.Is(err, row.readErr) {
					t.Errorf("the read's failure is not wrapped: %v", err)
				}
			} else if err != nil || rv != row.rv || !reflect.DeepEqual(doc, row.doc) {
				t.Fatalf("readEgressPolicyAt = %+v, %q, %v; want %+v at %q", doc, rv, err, row.doc, row.rv)
			}

			// world's read of the same ConfigMap comes to the same outcome.
			worldDoc, worldErr := readEgressPolicy(t.Context(), valueView{f})
			if !reflect.DeepEqual(worldDoc, doc) || (err == nil) != (worldErr == nil) ||
				(err != nil && (worldErr.Error() != err.Error() || kindOf(classified(worldErr)) != kindOf(classified(err)))) {
				t.Errorf("world reads %+v, %v; run reads %+v, %v", worldDoc, worldErr, doc, err)
			}
		})
	}
}

// ADR 0023 M2.6d (A23-47): egressPolicy mints each application's credential
// through the minter it is given, asked with the namespace and the
// application, and the document identifies each application by exactly the
// credential it was given. A failed mint fails it.
func TestEgressPolicyMintsThroughItsMinter(t *testing.T) {
	m, err := parser.Parse([]byte(twoAppManifest))
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	mint := func(namespace, app string) (string, error) {
		asked = append(asked, namespace+"/"+app)
		return "minted-for-" + namespace + "-" + app, nil
	}
	doc, credentials, err := egressPolicy(&policy.Document{Version: policy.Version}, "ns-a", *m, mint)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(asked, []string{"ns-a/api", "ns-a/web"}) {
		t.Errorf("the minter was asked for %q; want ns-a/api and ns-a/web, in manifest order", asked)
	}
	for _, app := range []string{"api", "web"} {
		want := "minted-for-ns-a-" + app
		if credentials[app] != want {
			t.Errorf("%s's credential is %q, not the minter's %q", app, credentials[app], want)
		}
		if got, ok := doc.Identify(want); !ok || got.Name != app || got.Namespace != "ns-a" {
			t.Errorf("the policy does not identify %s by the minter's credential: %+v, %t", app, got, ok)
		}
	}

	failed := errors.New("no randomness")
	if _, _, err := egressPolicy(&policy.Document{Version: policy.Version}, "ns-a", *m, func(string, string) (string, error) {
		return "", failed
	}); !errors.Is(err, failed) {
		t.Errorf("a failed mint = %v; want it returned", err)
	}
}
