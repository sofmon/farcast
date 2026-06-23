package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/fatline"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
)

type fakeCluster struct {
	applied  [][]byte
	rollouts int
	ip       string
	ipErr    error
	applyErr error
}

func (f *fakeCluster) Apply(_ context.Context, m []byte) error {
	f.applied = append(f.applied, m)
	return f.applyErr
}

func (f *fakeCluster) RolloutStatus(_ context.Context, _, _ string, _ time.Duration) error {
	f.rollouts++
	return nil
}

func (f *fakeCluster) WaitExternalIP(_ context.Context, _, _ string, _ time.Duration) (string, error) {
	if f.ipErr != nil {
		return "", f.ipErr
	}
	return f.ip, nil
}

type fakeConn struct {
	st     fatline.ConnStatus
	closed bool
}

func (f *fakeConn) Status(context.Context) (fatline.ConnStatus, error) { return f.st, nil }
func (f *fakeConn) Close() error                                       { f.closed = true; return nil }

func testEnv(dir config.Dir, mode output.Mode) (*Env, *bytes.Buffer) {
	var out, errb bytes.Buffer
	env := &Env{
		Out:       &out,
		Err:       &errb,
		In:        strings.NewReader(""), // not a terminal → non-interactive
		Printer:   &output.Printer{Mode: mode, Out: &out, Err: &errb},
		ConfigDir: dir,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return env, &out
}

func installedInstance(t *testing.T, dir config.Dir, name string) *config.InstanceMetadata {
	t.Helper()
	// t.TempDir() is 0755; the config store requires 0700 for credential safety.
	if err := os.Chmod(string(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := dir.CreateInstance(name); err != nil {
		t.Fatal(err)
	}
	meta := &config.InstanceMetadata{
		Name:      name,
		Provider:  "gke",
		Region:    "us-central1",
		Cluster:   "farcast-" + name,
		Status:    config.InstanceRunning,
		CostLimit: config.CostLimit{Amount: 50, Currency: "USD", Period: "monthly"},
	}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceKubeconfig(name, []byte("fake-kubeconfig")); err != nil {
		t.Fatal(err)
	}
	return meta
}

func TestConnectBootstrapsAndReports(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fc := &fakeCluster{ip: "34.0.0.1"}
	var dialed string
	c := newConnectCommand()
	c.assumeYes = true
	c.fatlineImage = "img:test"
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = func(_ context.Context, endpoint string, id tunnel.ClientIdentity) (tunnelConn, error) {
		dialed = endpoint
		if id.ServerName != "prod.fatline.farcast" {
			t.Errorf("dial serverName=%q, want prod.fatline.farcast", id.ServerName)
		}
		if len(id.Cert.Certificate) == 0 || id.CA == nil {
			t.Error("dial identity missing client cert or CA pool")
		}
		return &fakeConn{st: fatline.ConnStatus{Connected: true, Allowlist: []string{"api.stripe.com"}}}, nil
	}

	env, out := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	if ok, _ := dir.InstanceMTLSExists(name); !ok {
		t.Fatal("expected the mTLS identity to be minted on first connect")
	}
	if len(fc.applied) != 1 || len(fc.applied[0]) == 0 {
		t.Fatalf("expected exactly one non-empty Apply; got %d", len(fc.applied))
	}
	meta, _ := dir.LoadInstanceMetadata(name)
	if !meta.FatLineDeployed || meta.Carrier == nil || meta.Carrier.Endpoint != "34.0.0.1:8443" {
		t.Fatalf("carrier not recorded: deployed=%v carrier=%+v", meta.FatLineDeployed, meta.Carrier)
	}
	if meta.Carrier.ServerName != "prod.fatline.farcast" {
		t.Fatalf("carrier server name=%q", meta.Carrier.ServerName)
	}
	if dialed != "https://34.0.0.1:8443" {
		t.Fatalf("dialed=%q, want https://34.0.0.1:8443", dialed)
	}
	if !strings.Contains(out.String(), `connected to "prod"`) {
		t.Fatalf("output missing connected line:\n%s", out.String())
	}
}

func TestConnectCostGateRequiresYes(t *testing.T) {
	dir := config.Dir(t.TempDir())
	installedInstance(t, dir, "prod")

	fc := &fakeCluster{ip: "1.2.3.4"}
	c := newConnectCommand() // assumeYes stays false; env is non-interactive
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		t.Fatal("must not dial without cost confirmation")
		return nil, nil
	}

	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{"prod"})
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Fatalf("err=%v, want a usageError (cost not confirmed, non-interactive)", err)
	}
	if len(fc.applied) != 0 {
		t.Fatal("must not deploy without cost confirmation")
	}
	meta, _ := dir.LoadInstanceMetadata("prod")
	if meta.FatLineDeployed {
		t.Fatal("must not mark deployed when the cost gate was refused")
	}
}

func TestConnectStatusOnlyBeforeBootstrap(t *testing.T) {
	dir := config.Dir(t.TempDir())
	installedInstance(t, dir, "prod")

	fc := &fakeCluster{}
	c := newConnectCommand()
	c.statusOnly = true
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		t.Fatal("must not dial when not yet connected")
		return nil, nil
	}

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{"prod"}); err == nil {
		t.Fatal("expected an error for --status before the instance is connected")
	}
	if len(fc.applied) != 0 {
		t.Fatal("--status must never deploy")
	}
}

func TestConnectReconnectSkipsBootstrap(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	meta := installedInstance(t, dir, name)

	mat, err := identity.Mint(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceMTLS(name, toConfigMTLS(mat)); err != nil {
		t.Fatal(err)
	}
	meta.FatLineDeployed = true
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "9.9.9.9:8443", ServerName: identity.ServerName(name)}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}

	fc := &fakeCluster{}
	var dialed string
	c := newConnectCommand()
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = func(_ context.Context, endpoint string, _ tunnel.ClientIdentity) (tunnelConn, error) {
		dialed = endpoint
		return &fakeConn{st: fatline.ConnStatus{Connected: true}}, nil
	}

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatal(err)
	}
	if len(fc.applied) != 0 {
		t.Fatal("a reconnect must not re-deploy")
	}
	if dialed != "https://9.9.9.9:8443" {
		t.Fatalf("dialed=%q, want the stored endpoint", dialed)
	}
}

func TestConnectUnsupportedCarrier(t *testing.T) {
	dir := config.Dir(t.TempDir())
	installedInstance(t, dir, "prod")
	c := newConnectCommand()
	c.carrier = "cp-forward"
	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{"prod"})
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Fatalf("err=%v, want a usageError for an unsupported carrier", err)
	}
}

func TestConnectJSONOutput(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fc := &fakeCluster{ip: "34.0.0.2"}
	c := newConnectCommand()
	c.assumeYes = true
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		return &fakeConn{st: fatline.ConnStatus{Connected: true, Allowlist: []string{"api.x"}}}, nil
	}

	env, out := testEnv(dir, output.ModeJSON)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatal(err)
	}
	var res struct {
		Name      string `json:"name"`
		Connected bool   `json:"connected"`
		Carrier   string `json:"carrier"`
		Endpoint  string `json:"endpoint"`
		Identity  string `json:"identity"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("decode JSON result: %v\n%s", err, out.String())
	}
	if !res.Connected || res.Carrier != "nlb" || res.Endpoint != "34.0.0.2:8443" || res.Identity != "farcast://prod/operator" {
		t.Fatalf("result=%+v", res)
	}
}
