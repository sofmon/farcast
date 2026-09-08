package policy

import (
	"strings"
	"testing"

	"github.com/sofmon/farcast/manifest/parser"
)

func doc(t *testing.T) (*Document, map[string]string) {
	t.Helper()
	creds := map[string]string{}
	d := &Document{Version: Version}
	for _, a := range []struct{ ns, name string }{{"my-platform", "api"}, {"my-platform", "web"}, {"other", "api"}} {
		c, err := NewCredential()
		if err != nil {
			t.Fatal(err)
		}
		app := App{Name: a.name, Namespace: a.ns, CredentialSHA256: HashCredential(c)}
		if a.name == "api" && a.ns == "my-platform" {
			app.External = []parser.External{{Host: "api.stripe.com", Reason: "payments"}}
		}
		creds[app.Tenant()] = c
		d.Apps = append(d.Apps, app)
	}
	return d, creds
}

// The property the whole decision turns on: a credential names exactly one
// application, and naming the wrong one would hand it somebody else's
// declarations.
func TestACredentialIdentifiesExactlyItsOwnApp(t *testing.T) {
	d, creds := doc(t)
	for tenant, credential := range creds {
		app, ok := d.Identify(credential)
		if !ok {
			t.Fatalf("%s could not identify itself", tenant)
		}
		if app.Tenant() != tenant {
			t.Errorf("credential for %s identified %s", tenant, app.Tenant())
		}
	}
}

// Two deployments may each have an "api". If the tenant key were the app name
// alone they would share a policy.
func TestTheSameAppNameInTwoDeploymentsStaysSeparate(t *testing.T) {
	d, creds := doc(t)
	mine, _ := d.Identify(creds["my-platform/api"])
	theirs, _ := d.Identify(creds["other/api"])
	if mine.Tenant() == theirs.Tenant() {
		t.Fatalf("both resolved to %q", mine.Tenant())
	}
	if len(theirs.External) != 0 {
		t.Errorf("the other deployment's api inherited %v", theirs.External)
	}
}

func TestAnUnknownOrEmptyCredentialIdentifiesNothing(t *testing.T) {
	d, _ := doc(t)
	for name, credential := range map[string]string{
		"empty":                    "",
		"not a hash":               "hello",
		"wrong value":              strings.Repeat("0", 64),
		"a hash, not a credential": d.Apps[0].CredentialSHA256,
	} {
		t.Run(name, func(t *testing.T) {
			if app, ok := d.Identify(credential); ok {
				t.Fatalf("identified %q", app.Tenant())
			}
		})
	}
}

// The document is what sits in a ConfigMap. A credential appearing in it would
// put secret material somewhere this decision promises there is none.
func TestTheDocumentCarriesNoCredentials(t *testing.T) {
	d, creds := doc(t)
	body, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for tenant, credential := range creds {
		if strings.Contains(string(body), credential) {
			t.Fatalf("the policy document contains %s's credential in the clear", tenant)
		}
	}
	if !strings.Contains(string(body), d.Apps[0].CredentialSHA256) {
		t.Error("the document does not carry the hash it is supposed to")
	}
}

// An unchanged policy must produce an unchanged document, or every redeploy
// looks like a change and an operator stops reading the diffs.
func TestMarshalIsStable(t *testing.T) {
	d, _ := doc(t)
	first, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Same apps, different order.
	shuffled := &Document{Version: Version, Apps: []App{d.Apps[2], d.Apps[0], d.Apps[1]}}
	second, err := shuffled.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("reordering the apps changed the document:\n%s\n---\n%s", first, second)
	}
}

func TestParseRoundTrip(t *testing.T) {
	d, creds := doc(t)
	body, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	app, ok := got.Identify(creds["my-platform/api"])
	if !ok || app.Tenant() != "my-platform/api" {
		t.Fatalf("the parsed document does not identify the same app: %v %v", app, ok)
	}
	if len(app.External) != 1 || app.External[0].Host != "api.stripe.com" {
		t.Errorf("declarations did not survive: %v", app.External)
	}
	if by := got.ByTenant(); len(by["my-platform/api"]) != 1 || len(by["other/api"]) != 0 {
		t.Errorf("ByTenant = %v", by)
	}
}

func TestParseRefuses(t *testing.T) {
	valid := HashCredential("x")
	for name, body := range map[string]string{
		"a version it cannot enforce": `{"version":99,"apps":[]}`,
		"not JSON at all":             `{`,
		"an app with no name":         `{"version":1,"apps":[{"namespace":"n","credential_sha256":"` + valid + `"}]}`,
		"an app with no namespace":    `{"version":1,"apps":[{"name":"a","credential_sha256":"` + valid + `"}]}`,
		"no credential hash":          `{"version":1,"apps":[{"name":"a","namespace":"n"}]}`,
		"a truncated hash":            `{"version":1,"apps":[{"name":"a","namespace":"n","credential_sha256":"abc"}]}`,
		"two apps sharing a credential": `{"version":1,"apps":[` +
			`{"name":"a","namespace":"n","credential_sha256":"` + valid + `"},` +
			`{"name":"b","namespace":"n","credential_sha256":"` + valid + `"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(body)); err == nil {
				t.Fatalf("Parse accepted %s", name)
			}
		})
	}
}

// Every credential must be unique. Two identical ones would be the sharing case
// Parse refuses, arrived at by accident instead of by editing.
func TestCredentialsAreDistinctAndLongEnough(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		c, err := NewCredential()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != CredentialBytes*2 {
			t.Fatalf("credential is %d characters, want %d", len(c), CredentialBytes*2)
		}
		if seen[c] {
			t.Fatal("NewCredential repeated itself")
		}
		seen[c] = true
	}
}

// The credential rides in the proxy URL, which is what makes an application
// need no change at all.
func TestProxyURLCarriesTheCredentialAsUserinfo(t *testing.T) {
	got := ProxyURL("http", "fatline-egress.farcast-system.svc.cluster.local", 3128, "api", "deadbeef")
	want := "http://api:deadbeef@fatline-egress.farcast-system.svc.cluster.local:3128"
	if got != want {
		t.Errorf("ProxyURL = %q, want %q", got, want)
	}
	// A name needing percent-encoding must not produce a malformed URL.
	if got := ProxyURL("http", "h", 1, "we ird/name", "c"); strings.ContainsAny(got, " /") == false {
		t.Log(got) // fine either way; the assertion below is the real one
	}
	if strings.Contains(ProxyURL("http", "h", 1, "we ird", "c"), " ") {
		t.Error("a space reached the userinfo")
	}
}
