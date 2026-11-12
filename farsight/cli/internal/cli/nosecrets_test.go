package cli

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/shrike"
)

// ADR 0021 decision 9 (amended 2026-11-12): "instances and world open neither
// [the CA key nor the storage keyring]. A test runs them against a config
// directory where both are unreadable."
//
// Both are made mode 000, and the config package's read observer shows what
// was opened. Only the final dial is faked: the narrow identity loader and
// keyholder.New run for real against this directory.

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

func TestInstancesAndWorldNeverOpenTheCAKeyOrTheKeyring(t *testing.T) {
	f := newWorldFixture(t) // a connected instance whose fatline/ holds ca.key
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

	// world, with the default identity loader and seal client.
	monitor := shrikeServing(t, func(*shrike.Monitor) {})
	f.cmd.newSeal = nil
	f.cmd.connect = func(_ context.Context, _ string, id tunnel.ClientIdentity) (worldTunnel, error) {
		if len(id.Cert.Certificate) == 0 || id.CA == nil {
			return nil, errors.New("the dial was handed no identity")
		}
		return routedTunnel{monitor: monitor}, nil
	}
	doc, _ := f.run(t)
	wantSections(t, doc.Sections, map[string]string{"network": "read", "seal": kindTunnelUnreachable, "apps": "read", "spend": "read"})

	mu.Lock()
	defer mu.Unlock()
	for _, never := range []string{caKey, keyring} {
		if slices.Contains(opened, never) {
			t.Errorf("%s was opened", never)
		}
	}
	for _, want := range []string{"ca.crt", "client.crt", "client.key", "metadata.yaml"} {
		if !slices.ContainsFunc(opened, func(p string) bool { return filepath.Base(p) == want }) {
			t.Errorf("%s was never read, so the narrow loader did not run: %v", want, opened)
		}
	}
}
