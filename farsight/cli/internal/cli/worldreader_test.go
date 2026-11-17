package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/shrike"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

// ADR 0023 M2.4: 'world' reads the cluster in-process, as the instance's
// reader, through its default seam (openCluster), against a kubetest server.

// worldReaderFixture is a connected instance whose cluster is s, read by
// world as the instance's reader: readerInstance, granted, with an mTLS
// identity and a carrier, a kernel metering farcast-system and shop, a
// keyholder of two replicas, and shop deployed from this machine. s holds
// FarCast's own workloads, shop's api, both namespaces labelled as Planck
// labels them, the kernel's checkpoint and metered list, and the egress
// policy. The tunnel is a fake that reaches a real monitor and no keyholder.
type worldReaderFixture struct {
	s   *kubetest.Server
	dir config.Dir
	cmd *worldCommand
}

// worldReaderEmail is the loopback reader readerInstance records for atlas.
func worldReaderEmail() string { return readerName("atlas") + "@kubetest.invalid" }

func newWorldReaderFixture(t *testing.T, opts ...kubetest.Option) *worldReaderFixture {
	t.Helper()
	s := kubetest.New(t, opts...)
	dir, meta := readerInstance(t, s, "atlas", true)
	mat, err := identity.Mint("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceMTLS("atlas", toConfigMTLS(mat)); err != nil {
		t.Fatal(err)
	}
	meta.FatLineDeployed = true
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "192.0.2.10:8443", ServerName: identity.ServerName("atlas")}
	meta.Kernel = &config.Kernel{Deployed: true, Applied: true, Namespaces: []string{tcdeploy.DefaultNamespace, "shop"}}
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	meta.Deployments = map[string]config.Deployment{"shop": {Repository: "https://github.com/example/shop", StorageWired: true}}
	if err := dir.SaveInstanceMetadata("atlas", meta); err != nil {
		t.Fatal(err)
	}

	managed := map[string]any{"app.kubernetes.io/managed-by": "farcast"}
	for _, ns := range []string{tcdeploy.DefaultNamespace, "shop"} {
		s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns, "labels": managed}})
	}
	workload := func(kind, ns, name string, replicas int, images ...string) map[string]any {
		var containers []any
		for i, image := range images {
			containers = append(containers, map[string]any{"name": name + string(rune('a'+i)), "image": image})
		}
		return map[string]any{
			"apiVersion": "apps/v1", "kind": kind,
			"metadata": map[string]any{"name": name, "namespace": ns},
			"spec": map[string]any{
				"replicas": replicas,
				"selector": map[string]any{"matchLabels": map[string]any{"app": name}},
				"template": map[string]any{"spec": map[string]any{"containers": containers}},
			},
			"status": map[string]any{"readyReplicas": replicas},
		}
	}
	s.Put(workload("Deployment", tcdeploy.DefaultNamespace, "fatline", 2, vecFatLineImage, vecShrikeImage))
	s.Put(workload("Deployment", tcdeploy.DefaultNamespace, "technocore", 1, vecKernelImage))
	s.Put(workload("StatefulSet", tcdeploy.DefaultNamespace, "datasphered", 2, vecKeyholderImage))
	s.Put(workload("Deployment", "shop", "api", 1, vecRegistry+"/app/shop/api"+digestOf("6")))

	doc := policy.Document{Version: policy.Version, Apps: []policy.App{{Name: "api", Namespace: "shop",
		CredentialSHA256: credentialOf("a"), External: []parser.External{{Host: "api.example", Reason: "the api"}}}}}
	policyJSON, err := doc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	meterJSON, err := kernel.MarshalNamespaces([]string{tcdeploy.DefaultNamespace, "shop"})
	if err != nil {
		t.Fatal(err)
	}
	configMap := func(name, key, value string) map[string]any {
		return map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"name": name, "namespace": tcdeploy.DefaultNamespace},
			"data":     map[string]any{key: value},
		}
	}
	s.Put(configMap(kernel.DefaultCheckpointName, kernel.CheckpointKey(), vectorCheckpoint(t, nil)))
	s.Put(configMap(kernel.DefaultNamespacesName, kernel.NamespacesKey(), string(meterJSON)))
	s.Put(configMap(fldeploy.PolicyConfigMap, fldeploy.PolicyKey, string(policyJSON)))

	monitor := shrikeServing(t, func(*shrike.Monitor) {})
	return &worldReaderFixture{s: s, dir: dir, cmd: &worldCommand{
		now:   func() time.Time { return vectorNow },
		stamp: func() buildStamp { return vectorStamp },
		connect: func(_ context.Context, _ string, id tunnel.ClientIdentity) (worldTunnel, error) {
			if len(id.Cert.Certificate) == 0 || id.CA == nil {
				return nil, errors.New("the dial was handed no identity")
			}
			return routedTunnel{monitor: monitor}, nil
		},
	}}
}

// run runs world in JSON mode and returns its document, its stderr, and the
// document decoded.
func (f *worldReaderFixture) run(t *testing.T) (worldSections, map[string]any, []byte) {
	t.Helper()
	env, out, errb := testEnvBoth(f.dir, output.ModeJSON)
	if err := f.cmd.Run(context.Background(), env, []string{"atlas"}); err != nil {
		t.Fatalf("world: %v\nstderr: %s", err, errb.Bytes())
	}
	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.Bytes())
	}
	var sections worldSections
	b, _ := json.Marshal(raw["sections"])
	if err := json.Unmarshal(b, &sections); err != nil {
		t.Fatal(err)
	}
	return sections, raw, errb.Bytes()
}

// onlyTheReader fails t for any request s saw that a token other than the
// reader's authorized, or that carried none, and for any assertion the
// writer's key signed.
func onlyTheReader(t *testing.T, s *kubetest.Server) {
	t.Helper()
	reqs := s.Requests()
	if len(reqs) == 0 {
		t.Fatal("the cluster saw no request")
	}
	for _, r := range reqs {
		if r.As != "reader" {
			t.Errorf("%s %s?%s as %q; want only the reader", r.Method, r.Path, r.RawQuery, r.As)
		}
	}
}

// Design §10.2 and A18-15: whatever credential the shell around farcast
// holds, the cluster sees only the reader's token. Each of these would have
// reached a cluster read once: gcloud honours CLOUDSDK_AUTH_ACCESS_TOKEN over
// its files, Application Default Credentials name a key file, and the GKE
// auth plugin caches a token under the home directory and under the
// instance's own directory. The reads succeed, so the reader's token is
// shown to be the one that read, not merely the only one that tried.
func TestWorldPresentsOnlyTheReaderToken(t *testing.T) {
	f := newWorldReaderFixture(t)
	const planted = "ya29.planted-token-from-the-shell"
	t.Setenv("CLOUDSDK_AUTH_ACCESS_TOKEN", planted)
	adc := filepath.Join(t.TempDir(), "application_default_credentials.json")
	writer := f.s.Credential("writer")
	key, err := json.Marshal(map[string]string{
		"type": "service_account", "client_email": writer.Email,
		"private_key_id": writer.PrivateKeyID, "private_key": string(writer.PrivateKeyPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adc, key, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", adc)
	// A proxy proves nothing on loopback, which Go never proxies;
	// TestTransportsHaveNoProxy (internal/kube) carries that guarantee.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	home := t.TempDir()
	t.Setenv("HOME", home)
	cache := `{"current_context":"atlas","access_token":"` + planted + `","token_expiry":"2099-01-01T00:00:00Z"}`
	if err := os.MkdirAll(filepath.Join(home, ".kube"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(home, ".kube", "gke_gcloud_auth_plugin_cache"),
		filepath.Join(f.dir.InstancePath("atlas"), "gke_gcloud_auth_plugin_cache")} {
		if err := os.WriteFile(p, []byte(cache), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	sections, _, _ := f.run(t)
	wantSections(t, sections, map[string]string{"spend": "read", "apps": "read", "policy": "read", "network": "read"})
	onlyTheReader(t, f.s)
	for _, r := range f.s.Requests() {
		if strings.Contains(string(r.Body), planted) {
			t.Errorf("%s %s carried the planted token", r.Method, r.Path)
		}
	}
}

// P5 (A18-1), mutation 68a: the reader is bound in farcast-system and the
// metered namespaces only (P3), so a namespace Planck labelled that the
// kernel does not meter answers it 403. world reads every other namespace,
// marks that one's group with apps_error, keeps the apps section read, and
// still raises the alert that the namespace is not metered.
func TestWorldReadsTheNamespacesTheReaderMay(t *testing.T) {
	stream, err := renderReaderRBAC(worldReaderEmail(), []string{"shop"})
	if err != nil {
		t.Fatal(err)
	}
	f := newWorldReaderFixture(t, kubetest.WithRBAC(worldReaderEmail(), stream))
	f.s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{
		"name": "lab", "labels": map[string]any{"app.kubernetes.io/managed-by": "farcast"}}})
	f.s.Put(map[string]any{"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "notebook", "namespace": "lab"}, "spec": map[string]any{}})

	sections, raw, _ := f.run(t)
	wantSections(t, sections, map[string]string{"spend": "read", "apps": "read", "policy": "read"})
	onlyTheReader(t, f.s)

	var doc struct {
		Groups []worldGroup `json:"groups"`
		Alerts []worldAlert `json:"alerts"`
	}
	b, _ := json.Marshal(raw)
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	groups := map[string]worldGroup{}
	for _, g := range doc.Groups {
		groups[g.Namespace] = g
	}
	lab, shop := groups["lab"], groups["shop"]
	if lab.AppsError == nil || lab.AppsError.Kind != kindForbidden || len(lab.Apps) != 0 ||
		!strings.HasPrefix(lab.AppsError.Message, "the workloads in lab: ") {
		t.Errorf("lab = %+v (error %+v); want its workloads marked forbidden and none drawn", lab, lab.AppsError)
	}
	if strings.Contains(lab.AppsError.Message, worldReaderEmail()) {
		t.Errorf("lab's mark names the reader: %q", lab.AppsError.Message)
	}
	if shop.AppsError != nil || len(shop.Apps) != 1 || shop.Apps[0].Name != "api" || shop.Apps[0].State != stateRunning {
		t.Errorf("shop = %+v; want its api read", shop)
	}
	if !slices.ContainsFunc(doc.Alerts, func(a worldAlert) bool { return a.ID == "unmetered_namespace:component:kernel:lab" }) {
		t.Errorf("no unmetered_namespace alert for lab: %+v", doc.Alerts)
	}
	// The JSON carries the mark as null where the workloads were read.
	if g := raw["groups"].([]any); !strings.Contains(string(mustJSON(t, g)), `"apps_error":null`) {
		t.Errorf("a read group's apps_error is not null:\n%s", mustJSON(t, g))
	}
	// C-C24-1: the mark names the remedy that binds the reader there, once.
	// lab is not metered, so 'reader grant', which binds farcast-system and
	// the metered namespaces only, would not; metering it does.
	if m := lab.AppsError.Message; !strings.HasSuffix(m, meterLab) || strings.Count(m, meterLab) != 1 || strings.Contains(m, "reader grant") {
		t.Errorf("lab's mark = %q; want it to end %q, once, and never send the operator to 'reader grant'", m, meterLab)
	}

	// Mutation O44: the human reading marks the group whose applications
	// were not read, and counts it, so an empty group does not read as one
	// with no applications.
	env, out, errb := testEnvBoth(f.dir, output.ModeHuman)
	if err := f.cmd.Run(context.Background(), env, []string{"atlas"}); err != nil {
		t.Fatalf("world: %v\n%s", err, errb.String())
	}
	human := out.String()
	for _, want := range []string{"; 1 namespace not read\n", " — applications not read (forbidden)\n"} {
		if !strings.Contains(human, want) {
			t.Errorf("the human reading lacks %q:\n%s", want, human)
		}
	}
	for _, line := range strings.Split(human, "\n") {
		if strings.Contains(line, "applications not read") != strings.HasPrefix(strings.TrimSpace(line), "lab ") {
			t.Errorf("the mark is on the wrong group: %q", line)
		}
	}
}

// meterLab is the sentence a mark on the unmetered namespace lab of the
// instance atlas ends with: the command that binds the reader there.
const meterLab = "; the reader may read only farcast-system and the namespaces this machine records as metered: " +
	"run 'farcast kernel meter atlas lab', which meters lab and binds the reader there"

// C-C24-1: a mark names the remedy that works for its namespace. A metered
// namespace the reader is not bound in (its binding lost, or never applied)
// is what 'reader grant' fixes, since it applies every binding again; a 403
// that is not RBAC's is the endpoint's IAM, whatever the namespace. Each
// sentence is said once.
func TestWorldNamesTheRemedyForAnUnreadNamespace(t *testing.T) {
	read := func(t *testing.T, f *worldReaderFixture) *sectionProblem {
		t.Helper()
		f.s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{
			"name": "lab", "labels": map[string]any{"app.kubernetes.io/managed-by": "farcast"}}})
		sections, raw, _ := f.run(t)
		wantSections(t, sections, map[string]string{"spend": "read", "apps": "read", "policy": "read"})
		var doc struct {
			Groups []worldGroup `json:"groups"`
		}
		if err := json.Unmarshal(mustJSON(t, raw), &doc); err != nil {
			t.Fatal(err)
		}
		for _, g := range doc.Groups {
			if g.Namespace == "lab" && g.AppsError != nil && g.AppsError.Kind == kindForbidden {
				return g.AppsError
			}
		}
		t.Fatalf("lab is not marked forbidden: %+v", doc.Groups)
		return nil
	}
	t.Run("metered, not bound", func(t *testing.T) {
		stream, err := renderReaderRBAC(worldReaderEmail(), []string{"shop"})
		if err != nil {
			t.Fatal(err)
		}
		f := newWorldReaderFixture(t, kubetest.WithRBAC(worldReaderEmail(), stream))
		meta, err := f.dir.LoadInstanceMetadata("atlas")
		if err != nil {
			t.Fatal(err)
		}
		meta.Kernel.Namespaces = append(meta.Kernel.Namespaces, "lab")
		if err := f.dir.SaveInstanceMetadata("atlas", meta); err != nil {
			t.Fatal(err)
		}
		const grant = "; run 'farcast reader grant atlas'"
		if m := read(t, f).Message; !strings.HasSuffix(m, grant) || strings.Count(m, grant) != 1 || strings.Contains(m, "kernel meter") {
			t.Errorf("lab's mark = %q; want it to end %q, once", m, grant)
		}
	})
	t.Run("refused at the endpoint", func(t *testing.T) {
		f := newWorldReaderFixture(t)
		endpoint := kube.Status{}
		endpoint.Kind = "Error" // Google's JSON error, not a Status
		f.s.Fail(http.MethodGet, "/apis/apps/v1/namespaces/lab/deployments", http.StatusForbidden, endpoint)
		iam := "; " + msgReaderIAMRefused
		if m := read(t, f).Message; !strings.HasSuffix(m, iam) || strings.Count(m, iam) != 1 || strings.Contains(m, "kernel meter") {
			t.Errorf("lab's mark = %q; want it to end %q, once", m, iam)
		}
	})
}

// Mutation O23: an application a policy line names in a group the reader may
// not read is drawn with its state unknown, never not_deployed, and no caveat
// says it is not running: its workloads were never read.
func TestAnAppInAnUnreadGroupIsUnknown(t *testing.T) {
	stream, err := renderReaderRBAC(worldReaderEmail(), []string{"shop"})
	if err != nil {
		t.Fatal(err)
	}
	f := newWorldReaderFixture(t, kubetest.WithRBAC(worldReaderEmail(), stream))
	f.s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{
		"name": "lab", "labels": map[string]any{"app.kubernetes.io/managed-by": "farcast"}}})
	f.s.Put(map[string]any{"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "notebook", "namespace": "lab"}, "spec": map[string]any{}})
	doc := policy.Document{Version: policy.Version, Apps: []policy.App{
		{Name: "api", Namespace: "shop", CredentialSHA256: credentialOf("a"), External: []parser.External{{Host: "api.example", Reason: "the api"}}},
		{Name: "notebook", Namespace: "lab", CredentialSHA256: credentialOf("b"), External: []parser.External{{Host: "data.example", Reason: "the data"}}},
	}}
	policyJSON, err := doc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	f.s.Put(map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": fldeploy.PolicyConfigMap, "namespace": tcdeploy.DefaultNamespace},
		"data":     map[string]any{fldeploy.PolicyKey: string(policyJSON)}})

	sections, raw, _ := f.run(t)
	wantSections(t, sections, map[string]string{"spend": "read", "apps": "read", "policy": "read"})
	b := mustJSON(t, raw)
	var w struct {
		Instance struct {
			Caveats []string `json:"caveats"`
		} `json:"instance"`
		Groups []worldGroup `json:"groups"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	var notebook *worldApp
	for _, g := range w.Groups {
		if g.Namespace != "lab" {
			continue
		}
		if g.AppsError == nil {
			t.Errorf("lab is not marked: %+v", g)
		}
		for i := range g.Apps {
			if g.Apps[i].Name == "notebook" {
				notebook = &g.Apps[i]
			}
		}
	}
	if notebook == nil {
		t.Fatalf("lab/notebook, which the policy names, is not drawn:\n%s", b)
	}
	if notebook.State != stateUnknown {
		t.Errorf("lab/notebook is %q, want %q: its workloads were not read", notebook.State, stateUnknown)
	}
	if strings.Contains(string(b), "notebook is named by") {
		t.Errorf("a caveat says lab/notebook is not running:\n%s", b)
	}
}

// S-SEC-2: world.json carries no account, and the reader's email this
// machine records is one however it is spelled. openCluster's refusal of a
// reader that is not the derived one prints the recorded email, quoted
// (A18-8); world's sections carry it as <account>, in both output modes, for
// an email emailLike would not take for one — a dotless domain, an
// internationalized one, one holding a character that does not print — as
// for one it would. Nothing is sent.
func TestWorldNamesNoRecordedReader(t *testing.T) {
	for _, email := range []string{"alice.person@corp", "alice@exämple.com", "Alice@Example.Co", "alice@corp\x1b[2J"} {
		t.Run(strconv.QuoteToASCII(email), func(t *testing.T) {
			s := kubetest.New(t)
			dir, meta := readCommandsInstance(t, s, true)
			meta.Reader.Email = email
			if err := dir.SaveInstanceMetadata(readName, meta); err != nil {
				t.Fatal(err)
			}
			local, _, _ := strings.Cut(strings.ToLower(email), "@")
			for _, mode := range []string{"json", "human"} {
				var out, errb bytes.Buffer
				if code := run(context.Background(), []string{"farcast", "--config", dir.Path(), "-o", mode, "world", readName}, nil, &out, &errb); code != 0 {
					t.Fatalf("world -o %s: exit %d\n%s", mode, code, errb.String())
				}
				if printed := strings.ToLower(out.String() + errb.String()); strings.Contains(printed, local+"@") {
					t.Errorf("world -o %s names the recorded reader %q:\n%s", mode, email, out.String())
				}
				if mode == "json" {
					var doc struct {
						Sections map[string]sectionStatus `json:"sections"`
					}
					if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
						t.Fatal(err)
					}
					for _, section := range []string{"spend", "apps", "policy"} {
						p := doc.Sections[section].Error
						if p == nil || p.Kind != kindCredentialMissing || !strings.Contains(p.Message, `records the reader "<account>", which is not the reader`) {
							t.Errorf("world's %s = %+v; want the refusal, naming <account>", section, p)
						}
					}
				}
			}
			if n := len(s.Requests()); n != 0 {
				t.Errorf("world sent %d requests for a reader that is not the derived one", n)
			}
		})
	}
}

// S-SEC-2: scrubMessage replaces the reader email this machine records,
// whatever its case, as it is written and as %q writes it, before anything
// shaped like an email. A recorded value with no @ is no account, and
// nothing in a message is replaced for it.
func TestScrubMessageReplacesTheRecordedReader(t *testing.T) {
	for _, row := range []struct{ email, msg, want string }{
		{"alice.person@corp", `instance "atlas" records the reader "alice.person@corp", which is not`, `instance "atlas" records the reader "<account>", which is not`},
		{"alice.person@corp", "403 Forbidden: User ALICE.PERSON@CORP cannot list", "403 Forbidden: User <account> cannot list"},
		{"alice@exämple.com", `the reader "alice@EXÄMPLE.com", and alice@exämple.com`, `the reader "<account>", and <account>`},
		{"alice@corp\x1b[2J", fmt.Sprintf("records the reader %q", "alice@corp\x1b[2J"), `records the reader "<account>"`},
		{"bob", "bob ran the job", "bob ran the job"},
		{"", "nothing to replace", "nothing to replace"},
	} {
		meta := &config.InstanceMetadata{Reader: &config.Reader{Email: row.email}}
		if got := scrubMessage(row.msg, meta); got != row.want {
			t.Errorf("scrubMessage(%q) with the reader %q = %q, want %q", row.msg, row.email, got, row.want)
		}
	}
	if got := scrubMessage("a@b.example", &config.InstanceMetadata{}); got != "<account>" {
		t.Errorf("with no reader recorded: %q", got)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
