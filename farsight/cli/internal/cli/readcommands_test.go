package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
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
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
	tkube "github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/usage"
)

// ADR 0023 M2.4: ps, costs, usage and logs read the cluster in-process, as
// the instance's reader (design §7.3), through their default seams.

// readName is the instance the read commands' fixtures record.
const readName = "atlas"

// readApp is the application readCommandsInstance seeds: a Deployment in the
// metered namespace readNamespace, with one pod and a log.
const (
	readNamespace = "web"
	readApp       = "api"
	readLog       = "hello from the reader\n"
)

// readImage is readApp's image, as ps shows it.
var readImage = "reg.example/api@sha256:" + strings.Repeat("a", 64)

// readCommand is one read command as these tests run it: a fresh command each
// time, with its flags at their defaults and its seams left nil, so it opens
// the cluster through openCluster as the reader, exactly as farcast does.
type readCommand struct {
	name string
	args []string
	cmd  func() Command
	// seeded checks that out holds what readCommandsInstance seeded.
	seeded func(t *testing.T, out []byte)
}

func readCommands() []readCommand {
	return []readCommand{
		{"ps", []string{readName}, func() Command { return &psCommand{} }, func(t *testing.T, out []byte) {
			var res psResult
			if err := json.Unmarshal(out, &res); err != nil {
				t.Fatalf("%v:\n%s", err, out)
			}
			want := []psApp{{Namespace: readNamespace, Name: readApp, Ready: 2, Desired: 2, Tier: "app", Image: readImage}}
			for i := range res.Apps {
				res.Apps[i].Age = ""
			}
			if !slices.Equal(res.Apps, want) || len(res.Unreadable) != 0 {
				t.Errorf("ps listed %+v (unreadable %q); want %+v", res.Apps, res.Unreadable, want)
			}
		}},
		{"costs", []string{readName}, func() Command { return &costsCommand{} }, func(t *testing.T, out []byte) {
			var res costsResult
			if err := json.Unmarshal(out, &res); err != nil {
				t.Fatalf("%v:\n%s", err, out)
			}
			want := []appCost{{Namespace: readNamespace, Name: readApp, USD: 20}}
			if !slices.Equal(res.Apps, want) || res.Observed.Pods != 6 {
				t.Errorf("costs reported %+v from %d pods; want %+v from the checkpoint's 6", res.Apps, res.Observed.Pods, want)
			}
		}},
		{"usage", []string{readName}, func() Command { return &usageCommand{} }, func(t *testing.T, out []byte) {
			var res usageResult
			if err := json.Unmarshal(out, &res); err != nil {
				t.Fatalf("%v:\n%s", err, out)
			}
			if len(res.Apps) != 1 || res.Apps[0].Namespace != readNamespace || res.Apps[0].App != readApp || res.Apps[0].Pods != 2 {
				t.Errorf("usage reported %+v; want %s/%s on 2 pods", res.Apps, readNamespace, readApp)
			}
			if res.Replicas != 2 {
				t.Errorf("usage read %d FatLine replicas; want the seeded 2", res.Replicas)
			}
			// No carrier is recorded, so the tunnel half stops at the record.
			if !strings.Contains(res.NetworkError, "has no tunnel") {
				t.Errorf("usage's network half = %q; want the missing tunnel", res.NetworkError)
			}
		}},
		{"logs", []string{readName, readApp}, func() Command { return &logsCommand{} }, func(t *testing.T, out []byte) {
			if string(out) != readLog {
				t.Errorf("logs wrote %q; want the seeded log %q", out, readLog)
			}
		}},
	}
}

// readCommandsInstance is readerInstance, a loopback instance against s whose
// reader is registered under id "reader" beside a writer credentials.yaml
// registered under id "writer", with a kernel metering farcast-system and
// readNamespace, and with what ps, costs, usage and logs read seeded in s. It
// records no carrier.
func readCommandsInstance(t *testing.T, s *kubetest.Server, granted bool) (config.Dir, *config.InstanceMetadata) {
	t.Helper()
	dir, meta := readerInstance(t, s, readName, granted)
	meta.Kernel = &config.Kernel{Deployed: true, Applied: true, Namespaces: []string{tcdeploy.DefaultNamespace, readNamespace}}
	meta.CostLimit = config.CostLimit{Amount: 100, Currency: "USD", Period: "monthly"}
	if err := dir.SaveInstanceMetadata(readName, meta); err != nil {
		t.Fatal(err)
	}

	deployment := func(ns, name, tier, image string) map[string]any {
		return map[string]any{
			"apiVersion": "apps/v1", "kind": "Deployment",
			"metadata": map[string]any{"name": name, "namespace": ns, "labels": map[string]any{"farcast.sofmon.com/tier": tier}},
			"spec": map[string]any{
				"replicas": 2,
				"selector": map[string]any{"matchLabels": map[string]any{"app": name}},
				"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": image}}}},
			},
			"status": map[string]any{"readyReplicas": 2},
		}
	}
	configMap := func(name, key, value string) map[string]any {
		return map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"name": name, "namespace": tcdeploy.DefaultNamespace},
			"data":     map[string]any{key: value},
		}
	}
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)
	profiles := profilesFor(t, at, func(st *usage.Store) {
		for i := 0; i < 120; i++ {
			st.Record(at, kernel.AppKey(readNamespace, readApp), []usage.PodUsage{
				{Pod: "api-1", CPUMilli: 40, MemMiB: 110, RequestCPUMilli: 500, RequestMemMiB: 512},
				{Pod: "api-2", CPUMilli: 44, MemMiB: 118, RequestCPUMilli: 500, RequestMemMiB: 512},
			})
		}
	}, nil)

	s.Put(deployment(readNamespace, readApp, "app", readImage))
	s.Put(deployment(tcdeploy.DefaultNamespace, "fatline", "system", "reg.example/fatline@sha256:"+strings.Repeat("b", 64)))
	s.Put(configMap(kernel.DefaultCheckpointName, kernel.CheckpointKey(),
		checkpointFor(t, 100, 0.0304, map[string]float64{kernel.AppKey(readNamespace, readApp): 20}, nil)))
	s.Put(configMap(kernel.DefaultProfilesName, kernel.ProfilesKey(), profiles))
	s.Put(map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{
			"name": "api-1", "namespace": readNamespace,
			"labels":      map[string]any{"app": readApp},
			"annotations": map[string]any{kubetest.LogAnnotationPrefix + "app": readLog},
		},
		"spec": map[string]any{"containers": []any{map[string]any{"name": "app"}}},
	})
	return dir, meta
}

// runRead runs rc in JSON mode against dir, its flags at their defaults, as
// the router would, and returns what it printed and its error.
func runRead(t *testing.T, dir config.Dir, rc readCommand) (out, errb []byte, err error) {
	t.Helper()
	cmd := rc.cmd()
	fs := flag.NewFlagSet(rc.name, flag.ContinueOnError)
	cmd.SetFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	env, o, e := testEnvBoth(dir, output.ModeJSON)
	err = cmd.Run(t.Context(), env, rc.args)
	return o.Bytes(), e.Bytes(), err
}

// Design §7.3 and A18-15, mutation 60: each read command reads the cluster
// as the instance's reader. The installer's credentials.yaml is never opened
// (so neither the writer nor storage, which opens it, is), reader.key is,
// every request the cluster saw carried the reader's token, no assertion was
// signed with the writer's key, and each command returns what was seeded: a
// writer that refuses to open sends nothing, so the reads succeeding is what
// shows the reader read.
func TestReadCommandsPresentOnlyTheReaderToken(t *testing.T) {
	for _, rc := range readCommands() {
		t.Run(rc.name, func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := readCommandsInstance(t, s, true)
			reads := observeConfigReads(t)

			out, errb, err := runRead(t, dir, rc)
			if err != nil {
				t.Fatalf("%s: %v\nstderr: %s", rc.name, err, errb)
			}
			rc.seeded(t, out)

			got := reads()
			if slices.Contains(got, filepath.Join(dir.InstancePath(readName), "credentials.yaml")) {
				t.Errorf("%s opened the installer's credentials.yaml: %v", rc.name, got)
			}
			if !slices.Contains(got, filepath.Join(dir.InstancePath(readName), "reader.key")) {
				t.Errorf("%s never read reader.key: %v", rc.name, got)
			}
			reqs := s.Requests()
			if len(reqs) == 0 {
				t.Fatalf("%s sent nothing", rc.name)
			}
			for _, r := range reqs {
				if r.As != "reader" {
					t.Errorf("%s: %s %s as %q; want only the reader", rc.name, r.Method, r.Path, r.As)
				}
				if r.Path == "/token" && r.As == "writer" {
					t.Errorf("%s: an assertion was signed with the writer's key", rc.name)
				}
			}
		})
	}
}

// Design §3.5, mutation 60a: a reader that 'reader grant' has not verified
// read-only (GrantedAt zero) reads nothing. Each command refuses with
// errCredentialMissing, whose envelope's kind is credential_missing, and the
// cluster sees no request: not a mint, not a read. world prints its document,
// whose cluster sections carry that refusal. The kernel is recorded, so costs,
// usage and world's spend reach their reads.
func TestReadCommandsRefuseAnUnverifiedReader(t *testing.T) {
	for _, rc := range readCommands() {
		t.Run(rc.name, func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := readCommandsInstance(t, s, false)
			out, _, err := runRead(t, dir, rc)
			if !errors.Is(err, errCredentialMissing) || !strings.Contains(err.Error(), "has not been verified read-only") {
				t.Errorf("%s = %v; want the unverified reader refused as errCredentialMissing", rc.name, err)
			}
			if kind := kindOf(classified(err)); kind != kindCredentialMissing {
				t.Errorf("%s's envelope says %q, want %q", rc.name, kind, kindCredentialMissing)
			}
			if len(out) != 0 {
				t.Errorf("%s printed %q", rc.name, out)
			}
			if got := s.Requests(); len(got) != 0 {
				t.Errorf("%s sent %d requests for an unverified reader", rc.name, len(got))
			}
		})
	}
	t.Run("world", func(t *testing.T) {
		s := kubetest.New(t)
		dir, _ := readCommandsInstance(t, s, false)
		doc, errb := runWorldRead(t, dir)
		for _, section := range []string{"spend", "apps", "policy"} {
			p := doc.sections[section].Error
			if p == nil || p.Kind != kindCredentialMissing || !strings.Contains(p.Message, "has not been verified read-only") {
				t.Errorf("world's %s = %+v; want the unverified reader as credential_missing", section, p)
			}
		}
		if len(errb) != 0 {
			t.Errorf("world wrote to stderr: %s", errb)
		}
		if got := s.Requests(); len(got) != 0 {
			t.Errorf("world sent %d requests for an unverified reader", len(got))
		}
	})
}

// worldRead is a world document as runWorldRead decoded it.
type worldRead struct {
	sections map[string]sectionStatus
	messages string // every section message, one per line
}

// runWorldRead runs world in JSON mode against dir with its default seams,
// as farcast does, and returns its sections and its stderr.
func runWorldRead(t *testing.T, dir config.Dir) (worldRead, []byte) {
	t.Helper()
	env, o, e := testEnvBoth(dir, output.ModeJSON)
	if err := (&worldCommand{}).Run(t.Context(), env, []string{readName}); err != nil {
		t.Fatalf("world: %v", err)
	}
	var raw struct {
		Sections map[string]sectionStatus `json:"sections"`
	}
	if err := json.Unmarshal(o.Bytes(), &raw); err != nil {
		t.Fatalf("world printed no document (%v):\n%s", err, o.Bytes())
	}
	doc := worldRead{sections: raw.Sections}
	for _, st := range raw.Sections {
		if st.Error != nil {
			doc.messages += st.Error.Message + "\n"
		}
	}
	return doc, e.Bytes()
}

// A18-8 (A17-13): a read command hands openCluster the record as it was read,
// so the record is checked before anything is built or printed from it. A
// hostile email, project or recorded name sends nothing, is refused as
// errCredentialMissing, and reaches the operator only %q-quoted: in the
// envelope's message, on stdout and on stderr, through the router, in both
// output modes. A record naming another instance, however tidy its name, is
// refused before anything is opened.
func TestReadCommandsRefuseAnUnsafeRecord(t *testing.T) {
	for _, row := range []struct {
		name  string
		value string // the hostile value, which must only ever appear quoted
		edit  func(meta *config.InstanceMetadata, value string)
	}{
		{"an email", readerName(readName) + "@kubetest.invalid\x1b]0;owned\x07", func(meta *config.InstanceMetadata, v string) { meta.Reader.Email = v }},
		{"a project", "proj-\x1b[2Jtest", func(meta *config.InstanceMetadata, v string) { meta.Project = v }},
		{"a recorded name", readName + "\x1b[2J", func(meta *config.InstanceMetadata, v string) { meta.Name = v }},
		{"another instance's name", "other", func(meta *config.InstanceMetadata, v string) { meta.Name = v }},
	} {
		for _, rc := range readCommands() {
			t.Run(row.name+"/"+rc.name, func(t *testing.T) {
				s := kubetest.New(t)
				dir, meta := readCommandsInstance(t, s, true)
				row.edit(meta, row.value)
				if err := dir.SaveInstanceMetadata(readName, meta); err != nil {
					t.Fatal(err)
				}
				quoted := strconv.Quote(row.value)

				_, _, err := runRead(t, dir, rc)
				if !errors.Is(err, errCredentialMissing) {
					t.Fatalf("%s = %v; want a refusal matching errCredentialMissing", rc.name, err)
				}

				for _, mode := range []string{"json", "human"} {
					var out, errb bytes.Buffer
					args := append([]string{"farcast", "--config", dir.Path(), "-o", mode, rc.name}, rc.args...)
					if code := run(context.Background(), args, nil, &out, &errb); code != 1 {
						t.Errorf("%s -o %s: exit %d, want 1", rc.name, mode, code)
					}
					printed := out.String() + errb.String()
					if mode == "json" {
						var env struct {
							Error struct {
								Message string `json:"message"`
								Kind    string `json:"kind"`
							} `json:"error"`
						}
						if err := json.Unmarshal(out.Bytes(), &env); err != nil {
							t.Fatalf("%s: not an envelope (%v):\n%s", rc.name, err, out.Bytes())
						}
						printed = env.Error.Message + "\n" + errb.String()
						if !strings.Contains(env.Error.Message, quoted) {
							t.Errorf("%s: the message does not quote %s: %q", rc.name, quoted, env.Error.Message)
						}
						if env.Error.Kind != kindCredentialMissing {
							t.Errorf("%s: the envelope's kind is %q, want %q", rc.name, env.Error.Kind, kindCredentialMissing)
						}
					}
					if strings.Contains(strings.ReplaceAll(printed, quoted, ""), row.value) {
						t.Errorf("%s -o %s printed %q unquoted:\n%q", rc.name, mode, row.value, printed)
					}
				}
				if got := s.Requests(); len(got) != 0 {
					t.Errorf("%s sent %d requests for an unsafe record", rc.name, len(got))
				}
			})
		}
		// world carries the refusal in its cluster sections, prints its
		// document, and still prints the value only quoted.
		t.Run(row.name+"/world", func(t *testing.T) {
			s := kubetest.New(t)
			dir, meta := readCommandsInstance(t, s, true)
			row.edit(meta, row.value)
			if err := dir.SaveInstanceMetadata(readName, meta); err != nil {
				t.Fatal(err)
			}
			doc, errb := runWorldRead(t, dir)
			for _, section := range []string{"spend", "apps", "policy"} {
				if p := doc.sections[section].Error; p == nil || p.Kind != kindCredentialMissing {
					t.Errorf("world's %s = %+v; want the record refused as credential_missing", section, p)
				}
			}
			quoted := strconv.Quote(row.value)
			if strings.Contains(strings.ReplaceAll(doc.messages+string(errb), quoted, ""), row.value) {
				t.Errorf("world printed %q unquoted:\n%q", row.value, doc.messages+string(errb))
			}
			var out, errh bytes.Buffer
			if code := run(context.Background(), []string{"farcast", "--config", dir.Path(), "world", readName}, nil, &out, &errh); code != 0 {
				t.Errorf("world: exit %d, want 0:\n%s", code, errh.String())
			}
			if strings.Contains(strings.ReplaceAll(out.String()+errh.String(), quoted, ""), row.value) {
				t.Errorf("world's human reading printed %q unquoted:\n%q", row.value, out.String())
			}
			if got := s.Requests(); len(got) != 0 {
				t.Errorf("world sent %d requests for an unsafe record", len(got))
			}
		})
	}
}

// Design §8.1 and A18-10: when the cluster refuses the reader (403), the
// read commands append one sentence by the 403's shape. A Kubernetes Status,
// RBAC's refusal, says to run 'farcast reader grant'; anything else, Google's
// own JSON from the endpoint's IAM check, says what IAM needs. The error
// still matches tkube.ErrForbidden, so its kind can be found, and ps keeps a
// partial read as a listing whose row carries the sentence.
func TestReadCommandsSayWhatAForbiddenReadNeeds(t *testing.T) {
	const grant = "; run 'farcast reader grant atlas'"
	const iam = "; " + msgReaderIAMRefused
	rbac := kube.Status{}
	endpoint := kube.Status{}
	endpoint.Kind = "Error" // Google's JSON error, not a Status
	deployments := func(ns string) string { return "/apis/apps/v1/namespaces/" + ns + "/deployments" }
	configMap := func(name string) string {
		return "/api/v1/namespaces/" + tcdeploy.DefaultNamespace + "/configmaps/" + name
	}
	commands := map[string]readCommand{}
	for _, rc := range readCommands() {
		commands[rc.name] = rc
	}
	for _, row := range []struct {
		name    string
		command string
		paths   []string
		st      kube.Status
		suffix  string
	}{
		{"ps, every namespace refused by RBAC", "ps", []string{deployments(tcdeploy.DefaultNamespace), deployments(readNamespace)}, rbac, grant},
		{"ps, every namespace refused at the endpoint", "ps", []string{deployments(tcdeploy.DefaultNamespace), deployments(readNamespace)}, endpoint, iam},
		{"costs, by RBAC", "costs", []string{configMap(kernel.DefaultCheckpointName)}, rbac, grant},
		{"costs, at the endpoint", "costs", []string{configMap(kernel.DefaultCheckpointName)}, endpoint, iam},
		{"usage, by RBAC", "usage", []string{configMap(kernel.DefaultProfilesName)}, rbac, grant},
		{"usage, at the endpoint", "usage", []string{configMap(kernel.DefaultProfilesName)}, endpoint, iam},
		{"logs, finding the app, by RBAC", "logs", []string{deployments(tcdeploy.DefaultNamespace), deployments(readNamespace)}, rbac, grant},
		{"logs, finding the app, at the endpoint", "logs", []string{deployments(tcdeploy.DefaultNamespace), deployments(readNamespace)}, endpoint, iam},
		{"logs, reading it, by RBAC", "logs", []string{deployments(readNamespace) + "/" + readApp}, rbac, grant},
		{"logs, reading it, at the endpoint", "logs", []string{deployments(readNamespace) + "/" + readApp}, endpoint, iam},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := readCommandsInstance(t, s, true)
			for _, p := range row.paths {
				s.Fail(http.MethodGet, p, http.StatusForbidden, row.st)
			}
			_, _, err := runRead(t, dir, commands[row.command])
			if err == nil || !strings.HasSuffix(err.Error(), row.suffix) {
				t.Fatalf("%s = %v; want it to end %q", row.command, err, row.suffix)
			}
			if !errors.Is(err, tkube.ErrForbidden) {
				t.Errorf("%s = %v; it no longer matches tkube.ErrForbidden", row.command, err)
			}
			if kind := kindOf(classified(err)); kind != kindForbidden {
				t.Errorf("%s's envelope says %q, want %q", row.command, kind, kindForbidden)
			}
			if strings.Count(err.Error(), row.suffix) != 1 {
				t.Errorf("%s = %v; the sentence is there more than once", row.command, err)
			}
		})
	}

	// A partial read stays a listing, exit 0, and its row says what to do.
	s := kubetest.New(t)
	dir, _ := readCommandsInstance(t, s, true)
	s.Fail(http.MethodGet, deployments(readNamespace), http.StatusForbidden, rbac)
	out, _, err := runRead(t, dir, commands["ps"])
	if err != nil {
		t.Fatalf("ps with one namespace refused = %v; want a partial listing", err)
	}
	var res psResult
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Unreadable) != 1 || !strings.HasPrefix(res.Unreadable[0], readNamespace+": ") || !strings.HasSuffix(res.Unreadable[0], grant) {
		t.Errorf("ps's unreadable rows = %q; want %s's, ending %q", res.Unreadable, readNamespace, grant)
	}
}

// S-SEC-1: ps's human listing puts nothing the cluster said in front of the
// operator raw. A namespace it could not read is a row of the API server's
// own words, here a 403 whose Status message carries an escape, a BEL, a
// carriage return and a bidi override. The row goes through terminalText, as
// world's and instances' rows do, so it keeps its evidence, quoted, and loses
// its power over the terminal. The listing is still partial, exit 0.
func TestPsQuotesWhatTheClusterSaid(t *testing.T) {
	const hostile = "denied \x1b]0;pwned\x07 \x1b[31mRED\x1b[0m\rOVERWRITE \u202e"
	s := kubetest.New(t)
	dir, _ := readCommandsInstance(t, s, true)
	st := kube.Status{}
	st.Message = hostile
	s.Fail(http.MethodGet, "/apis/apps/v1/namespaces/"+readNamespace+"/deployments", http.StatusForbidden, st)

	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"farcast", "--config", dir.Path(), "ps", readName}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("ps: exit %d\n%s%s", code, out.String(), errb.String())
	}
	shown := out.String()
	if strings.ContainsAny(shown+errb.String(), "\x1b\x07\r\u202e") || !output.Printable(strings.ReplaceAll(shown, "\n", "")) {
		t.Errorf("ps printed the cluster's text raw:\n%q", shown)
	}
	for _, want := range []string{"Could not read ", readNamespace + ": ", `\x1b]0;pwned\a`, `\u202e`, "This listing is partial."} {
		if !strings.Contains(shown, want) {
			t.Errorf("the listing lacks %q:\n%s", want, shown)
		}
	}
}

// Mutation O9d: in logs, a 403 by RBAC among several namespaces' failures is
// found whatever came first, and the RBAC sentence is said, once: the
// operator is sent to 'reader grant' even when another namespace's 403 came
// from the endpoint.
func TestLogsFindsAnRBACRefusalAmongSeveralNamespaces(t *testing.T) {
	const grant = "; run 'farcast reader grant atlas'"
	deployments := func(ns string) string { return "/apis/apps/v1/namespaces/" + ns + "/deployments" }
	endpoint := kube.Status{}
	endpoint.Kind = "Error" // Google's JSON error, not a Status
	var logs readCommand
	for _, rc := range readCommands() {
		if rc.name == "logs" {
			logs = rc
		}
	}
	for _, iam := range []string{tcdeploy.DefaultNamespace, readNamespace} {
		t.Run("the endpoint's 403 in "+iam, func(t *testing.T) {
			s := kubetest.New(t)
			dir, _ := readCommandsInstance(t, s, true)
			for _, ns := range []string{tcdeploy.DefaultNamespace, readNamespace} {
				st := kube.Status{} // RBAC's refusal
				if ns == iam {
					st = endpoint
				}
				s.Fail(http.MethodGet, deployments(ns), http.StatusForbidden, st)
			}
			_, _, err := runRead(t, dir, logs)
			if err == nil || !strings.HasSuffix(err.Error(), grant) || strings.Count(err.Error(), grant) != 1 {
				t.Errorf("logs = %v; want it to end %q, once", err, grant)
			}
			if err != nil && strings.Contains(err.Error(), msgReaderIAMRefused) {
				t.Errorf("logs = %v; it says the IAM sentence as well", err)
			}
		})
	}
}

// Mutation O33 (A18-9): an open failure no kind names is internal in each of
// world's cluster sections, never an empty kind. A reader.key that exists
// and cannot be read is one: LoadReaderKey's own error, which clusterKind
// does not know. Nothing is sent.
func TestWorldKindsAnOpenFailureNoKindNamesInternal(t *testing.T) {
	s := kubetest.New(t)
	dir, _ := readCommandsInstance(t, s, true)
	key := filepath.Join(dir.InstancePath(readName), "reader.key")
	if err := os.Chmod(key, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(key, 0o600) })
	if _, err := os.ReadFile(key); err == nil {
		t.Skip("running as a user who can read a mode-000 file; the test would prove nothing")
	}
	doc, _ := runWorldRead(t, dir)
	for _, section := range []string{"spend", "apps", "policy"} {
		if p := doc.sections[section].Error; p == nil || p.Kind != kindInternal || !strings.Contains(p.Message, "reader.key") {
			t.Errorf("world's %s = %+v; want the unreadable key as internal", section, p)
		}
	}
	if n := len(s.Requests()); n != 0 {
		t.Errorf("world sent %d requests with a key it could not read", n)
	}
}

// Mutation O49: logs hands openCluster the command's stderr, so through its
// default seam the --previous note for a container with no previous instance
// reaches stderr, and stdout carries the application's bytes alone (here,
// none).
func TestLogsWritesThePreviousNoteToStderr(t *testing.T) {
	s := kubetest.New(t)
	dir, _ := readCommandsInstance(t, s, true)
	cmd := &logsCommand{}
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	cmd.SetFlags(fs)
	if err := fs.Parse([]string{"--previous"}); err != nil {
		t.Fatal(err)
	}
	env, out, errb := testEnvBoth(dir, output.ModeJSON)
	if err := cmd.Run(t.Context(), env, []string{readName, readApp}); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q; want nothing", out.String())
	}
	if want := "api-1/app: no previous instance\n"; !strings.Contains(errb.String(), want) {
		t.Errorf("stderr = %q; want the note %q", errb.String(), want)
	}
}
