package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
)

// ADR 0021 decision 9 (amended 2026-11-12): "instances and world open neither
// [the CA key nor the storage keyring]. A test runs them against a config
// directory where both are unreadable." ADR 0023 M2.4 adds the installer's
// credential to what world never opens, and the reader's key to what
// instances never opens.
//
// Each is made mode 000, or watched, and the config package's read observer
// shows what was opened. Only the final dial is faked: the narrow identity
// loader and keyholder.New run for real against this directory, and the
// cluster is a kubetest server read through openCluster.

// routedTunnel sends the monitor's route to a real monitor and refuses the
// rest.
type routedTunnel struct{ monitor *fakeStreamDialer }

func (r routedTunnel) DialStream(ctx context.Context, route string, ordinal int) (net.Conn, error) {
	if route == fldeploy.ShrikeStreamRoute {
		return r.monitor.DialStream(ctx, route, ordinal)
	}
	return nil, errors.New("no keyholder in this test")
}

func (routedTunnel) Close() error { return nil }

// Design §7.3 and A18-15, mutation 59: world reads the cluster as the
// instance's reader and never mints a token for the installer, who can
// write. Its fixture holds the installer's credentials.yaml, registered with
// the cluster as "writer", beside the reader's key, registered as "reader".
// world never opens credentials.yaml, reads reader.key, is answered only as
// the reader, never signs an assertion with the writer's key, and reads
// spend, apps and policy. Since ADR 0023 M2.5 the fixture's writer opens
// too, and could read all of it, so a world that read as the writer would
// now reach the server and fail the As checks: the test is stronger than
// when a writer refused to open. instances and world also open neither the
// CA key nor the keyring (ADR 0021 decision 9).
func TestWorldNeverOpensAWriterCredential(t *testing.T) {
	f := newWorldReaderFixture(t) // a connected instance whose fatline/ holds ca.key
	keys, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := keys.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.dir.CreateInstanceKeyring("atlas", encoded); err != nil {
		t.Fatal(err)
	}
	caKey := filepath.Join(f.dir.InstancePath("atlas"), "fatline", "ca.key")
	keyring := f.dir.InstanceKeyringPath("atlas")
	for _, p := range []string{caKey, keyring} {
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	}
	if _, err := os.ReadFile(caKey); err == nil {
		t.Skip("running as a user who can read a mode-000 file; the test would prove nothing")
	}

	var mu sync.Mutex
	var opened []string
	stop := config.ObserveReads(func(p string) {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasPrefix(p, f.dir.Path()) {
			opened = append(opened, p)
		}
	})
	defer stop()

	// instances, as the router runs it.
	if out, code := runRouter(t, "--config", f.dir.Path(), "-o", "json", "instances"); code != 0 || !strings.Contains(string(out), `"name":"atlas"`) {
		t.Fatalf("instances: exit %d\n%s", code, out)
	}

	// world, through its default cluster seam, identity loader and seal
	// client.
	sections, _, _ := f.run(t)
	wantSections(t, sections, map[string]string{"network": "read", "seal": kindTunnelUnreachable, "apps": "read", "spend": "read", "policy": "read"})
	onlyTheReader(t, f.s)
	for _, r := range f.s.Requests() {
		if r.Path == "/token" && r.As == "writer" {
			t.Error("an assertion was signed with the writer's key")
		}
	}

	mu.Lock()
	defer mu.Unlock()
	credentials := filepath.Join(f.dir.InstancePath("atlas"), "credentials.yaml")
	for _, never := range []string{caKey, keyring, credentials} {
		if slices.Contains(opened, never) {
			t.Errorf("%s was opened", never)
		}
	}
	for _, want := range []string{"ca.crt", "client.crt", "client.key", "metadata.yaml", "reader.key"} {
		if !slices.ContainsFunc(opened, func(p string) bool { return filepath.Base(p) == want }) {
			t.Errorf("%s was never read, so world did not read as it must: %v", want, opened)
		}
	}
}

// Design §8.2 and §10.2, mutation 65: instances reports the reader's state
// from the record and the key file's presence alone. With reader.key at mode
// 000 it still says "granted", and never opened the key.
func TestInstancesNeverOpensTheReaderKey(t *testing.T) {
	s := kubetest.New(t)
	dir, _ := readerInstance(t, s, "atlas", true)
	key := filepath.Join(dir.InstancePath("atlas"), "reader.key")
	if err := os.Chmod(key, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(key, 0o600) })
	if _, err := os.ReadFile(key); err == nil {
		t.Skip("running as a user who can read a mode-000 file; the test would prove nothing")
	}
	reads := observeConfigReads(t)

	out, code := runRouter(t, "--config", dir.Path(), "-o", "json", "instances")
	if code != 0 {
		t.Fatalf("instances: exit %d\n%s", code, out)
	}
	var doc struct {
		Instances []struct {
			Name     string          `json:"name"`
			Reader   string          `json:"reader"`
			Migrated *bool           `json:"migrated"`
			Error    *sectionProblem `json:"error"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	if len(doc.Instances) != 1 || doc.Instances[0].Reader != readerGranted || doc.Instances[0].Error != nil ||
		doc.Instances[0].Migrated == nil || *doc.Instances[0].Migrated {
		t.Errorf("instances = %s; want atlas's reader granted, and not migrated", out)
	}
	if got := reads(); slices.Contains(got, key) {
		t.Errorf("instances opened reader.key: %v", got)
	}
	if n := len(s.Requests()); n != 0 {
		t.Errorf("instances sent %d requests", n)
	}
}

// Mutation 65b: instances never opens reader.key, however the open is
// spelled, an open whose error is dropped included, which the mode-000 key
// above cannot see: such an open fails silently and the stat still says
// granted. A FIFO in reader.key's place stats as present, and any open of it
// for reading blocks until a writer comes, so an open is a hang. instances
// must answer within the bound with the reader granted.
func TestInstancesNeverOpensAFIFOReaderKey(t *testing.T) {
	s := kubetest.New(t)
	dir, _ := readerInstance(t, s, "atlas", true)
	key := filepath.Join(dir.InstancePath("atlas"), "reader.key")
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(key, 0o600); err != nil {
		t.Skipf("no FIFO on this system: %v", err)
	}
	done := make(chan []byte, 1)
	go func() {
		var out, errb bytes.Buffer
		run(context.Background(), []string{"farcast", "--config", dir.Path(), "-o", "json", "instances"}, strings.NewReader(""), &out, &errb)
		done <- out.Bytes()
	}()
	select {
	case out := <-done:
		if !strings.Contains(string(out), `"reader":"granted"`) {
			t.Errorf("instances = %s; want atlas's reader granted", out)
		}
	case <-time.After(5 * time.Second):
		// A reader is blocked in its open: a writer's open, which does not
		// block with one waiting, releases it, and its close ends the read.
		if f, err := os.OpenFile(key, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		<-done
		t.Fatal("instances opened reader.key: it blocked on a FIFO")
	}
	if n := len(s.Requests()); n != 0 {
		t.Errorf("instances sent %d requests", n)
	}
}
