package rehearsal

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/fatline/identity"
)

// The state directory (D3) and the instance record in it (D4).

const (
	// gcloudConfigName is the rehearsal's own gcloud configuration, the one
	// whose account the instance pins.
	gcloudConfigName = "rehearsal"
	// decoyConfigName is the configuration gcloud's active_config names: the
	// same project under another account. Nothing may ever read as it.
	decoyConfigName = "work"
	decoyAccount    = "someone@work.invalid"
	// mismatchProject is config_rehearsal's project in identity-mismatch.
	mismatchProject = "another-project"
	// keeperDevice is the one enrolled keeper.
	keeperDevice = "phone"
	// shopNamespace is the one application namespace.
	shopNamespace = "shop"
	callsLog      = "calls.log"
	harnessSubdir = "harness"
)

// The harness's own leaves, written on the first Start and read on a restart.
const (
	khCertFile     = "keyholder-server.crt"
	khKeyFile      = "keyholder-server.key"
	keeperCertFile = "keeper-" + keeperDevice + ".crt"
	keeperKeyFile  = "keeper-" + keeperDevice + ".key"
)

// The three fake tools, each a symlink to the harness binary.
const (
	toolKubectl = "kubectl"
	toolPlugin  = "gke-gcloud-auth-plugin"
	toolGCloud  = "gcloud"
)

// component names, as FatLine's, the kernel's and the keyholder's deploy
// packages name their workloads ('world' finds them by these).
const (
	nameFatLine   = "fatline"
	nameShrike    = "shrike"
	nameKernel    = "technocore"
	nameKeyholder = "datasphered"
)

// material is the TLS material a running rig needs, and nothing more: never
// the CA's private key.
type material struct {
	caCert                []byte
	serverCert, serverKey []byte // FatLine's
	khCert, khKey         []byte // the keyholders'
	keeperCert, keeperKey []byte // the keeper device's
}

// imageRef is a component's digest-pinned reference in the rehearsal's
// placeholder registry: the digest is the name's own hash, so every
// component's is distinct and nothing is random.
func imageRef(name string) string {
	sum := sha256.Sum256([]byte("farcast-rehearsal/image/" + name))
	return "registry.rehearsal.invalid/farcast/" + name + "@sha256:" + hex.EncodeToString(sum[:])
}

// hexOf is n hex digits derived from a label.
func hexOf(label string, n int) string {
	sum := sha256.Sum256([]byte("farcast-rehearsal/" + label))
	return strings.Repeat(hex.EncodeToString(sum[:]), 2)[:n]
}

// toolLinks are the three links and the directory each lives in.
func toolLinks(d Dirs) map[string]string {
	return map[string]string{
		toolKubectl: filepath.Join(d.KubeBin, toolKubectl),
		toolPlugin:  filepath.Join(d.SDKBin, toolPlugin),
		toolGCloud:  filepath.Join(d.SDKBin, toolGCloud),
	}
}

// makeLayout writes a new rehearsal into root, which exists and is empty. It
// returns the spec (written last, so a directory a failed Start leaves is
// never mistaken for a rehearsal) and the material the servers need.
func makeLayout(root string, s Spec, tools, tunnelAddr string, now time.Time) (material, error) {
	d := s.Dirs
	for _, dir := range []string{d.GCloud, filepath.Join(d.GCloud, "configurations"), filepath.Join(root, harnessSubdir), d.KubeBin, d.SDKBin} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return material{}, err
		}
	}
	// Every parent the layout made is the owner's alone, as B4 asks of a
	// tool's directory.
	for _, dir := range []string{filepath.Join(root, "kube"), filepath.Join(root, "sdk")} {
		if err := os.Chmod(dir, 0o700); err != nil {
			return material{}, err
		}
	}

	// D4.1: the identity. The CA key is in memory here, and only here.
	inst := s.Instance
	mint, err := identity.Mint(inst)
	if err != nil {
		return material{}, err
	}
	khCert, khKey, err := identity.IssueKeyholderServer(mint.CACertPEM, mint.CAKeyPEM, inst)
	if err != nil {
		return material{}, err
	}
	keeperCert, keeperKey, err := identity.IssueKeeperClient(mint.CACertPEM, mint.CAKeyPEM, inst, keeperDevice, []byte("rehearsal-bundle"))
	if err != nil {
		return material{}, err
	}
	m := material{
		caCert: mint.CACertPEM, serverCert: mint.ServerCertPEM, serverKey: mint.ServerKeyPEM,
		khCert: khCert, khKey: khKey, keeperCert: keeperCert, keeperKey: keeperKey,
	}
	for name, data := range map[string][]byte{khCertFile: khCert, khKeyFile: khKey, keeperCertFile: keeperCert, keeperKeyFile: keeperKey} {
		if err := os.WriteFile(filepath.Join(root, harnessSubdir, name), data, 0o600); err != nil {
			return material{}, err
		}
	}

	cfg := config.Dir(d.Config)
	if err := cfg.CreateInstance(inst); err != nil {
		return material{}, err
	}
	if err := cfg.SaveInstanceMTLS(inst, config.MTLSMaterial{
		CACertPEM: mint.CACertPEM, CAKeyPEM: mint.CAKeyPEM,
		ClientCertPEM: mint.ClientCertPEM, ClientKeyPEM: mint.ClientKeyPEM,
		ServerCertPEM: mint.ServerCertPEM, ServerKeyPEM: mint.ServerKeyPEM,
	}); err != nil {
		return material{}, err
	}
	// Unreadable from here on, so a read that opened it would fail.
	if err := os.Chmod(caKeyPath(cfg, inst), 0); err != nil {
		return material{}, err
	}
	if err := cfg.CreateInstanceKeyring(inst, []byte("# A rehearsal placeholder. It holds no key, and nothing may open it.\n")); err != nil {
		return material{}, err
	}
	if err := os.Chmod(cfg.InstanceKeyringPath(inst), 0); err != nil {
		return material{}, err
	}
	if err := cfg.SaveInstanceKubeconfig(inst, kubeconfigYAML(inst)); err != nil {
		return material{}, err
	}

	// D4.2: the record. Every name in it is a .invalid placeholder.
	token, err := identity.LeafTokenPEM(keeperCert)
	if err != nil {
		return material{}, err
	}
	expires, err := notAfter(keeperCert)
	if err != nil {
		return material{}, err
	}
	meta := &config.InstanceMetadata{
		Name: inst, Provider: "gke", Project: s.Project, Region: "rehearsal-local", Cluster: "farcast-" + inst,
		Endpoint: "control-plane.rehearsal.invalid", Status: config.InstanceRunning,
		CostLimit: config.CostLimit{Amount: 50, Currency: "USD", Period: "monthly"},
		CreatedAt: now, UpdatedAt: now,
		CloudLogging: config.CloudLoggingSystem, GCloudAccount: s.Account, FatLineDeployed: true,
		Carrier:  &config.Carrier{Type: "rehearsal", Endpoint: tunnelAddr, ServerName: identity.ServerName(inst)},
		Registry: &config.Registry{Prefix: "registry.rehearsal.invalid/farcast", FatLineDigest: s.Images[nameFatLine]},
		Kernel: &config.Kernel{
			Deployed: true, Applied: true, Image: s.Images[nameKernel], Namespaces: []string{"farcast-system", shopNamespace},
			Limit: 50, Currency: "USD", Period: "monthly",
		},
		Keyholder: &config.Keyholder{Deployed: true, Image: s.Images[nameKeyholder], Replicas: 2},
		Keepers:   []config.Keeper{{Device: keeperDevice, EnrolledAt: now, Expires: expires, LeafTokens: []string{token}}},
		Deployments: map[string]config.Deployment{shopNamespace: {
			Repository: "https://git.rehearsal.invalid/shop", Ref: "refs/heads/main",
			Commit: hexOf("shop-commit", 40), ManifestDigest: "sha256:" + hexOf("shop-manifest", 64),
			DeployedAt: now.Add(-time.Hour), StorageWired: true,
		}},
	}
	if err := cfg.SaveInstanceMetadata(inst, meta); err != nil {
		return material{}, err
	}

	// gcloud's configuration directory, with a decoy active.
	if err := os.WriteFile(filepath.Join(d.GCloud, "active_config"), []byte(decoyConfigName), 0o600); err != nil {
		return material{}, err
	}
	if err := os.WriteFile(filepath.Join(d.GCloud, "configurations", "config_"+decoyConfigName),
		[]byte(iniCore(decoyAccount, s.Project)), 0o600); err != nil {
		return material{}, err
	}
	if err := writeGCloudConfig(s, s.Scenario); err != nil {
		return material{}, err
	}

	for _, link := range toolLinks(d) {
		if err := os.Symlink(tools, link); err != nil {
			return material{}, err
		}
	}
	if err := os.WriteFile(filepath.Join(root, callsLog), nil, 0o600); err != nil {
		return material{}, err
	}
	return m, writeSpec(root, s)
}

// loadLayout reads what a restart needs from a rehearsal a stopped harness
// left: the harness's leaves, the instance's CA certificate and FatLine's
// leaf, and the tunnel address the record pins. It never opens ca.key, and it
// issues nothing.
func loadLayout(s Spec, tools string) (material, string, error) {
	d := s.Dirs
	for name, link := range toolLinks(d) {
		got, err := os.Readlink(link)
		if err != nil || got != tools {
			if err == nil {
				err = fmt.Errorf("its %s links to %s", name, got)
			}
			return material{}, "", fmt.Errorf("this directory's tools do not link to %s (%v); start a new rehearsal in a new directory", tools, err)
		}
	}
	read := func(path string) ([]byte, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		return b, nil
	}
	var m material
	var err error
	harness := filepath.Join(d.Root, harnessSubdir)
	fat := filepath.Join(config.Dir(d.Config).InstancePath(s.Instance), "fatline")
	for _, f := range []struct {
		path string
		into *[]byte
	}{
		{filepath.Join(harness, khCertFile), &m.khCert},
		{filepath.Join(harness, khKeyFile), &m.khKey},
		{filepath.Join(harness, keeperCertFile), &m.keeperCert},
		{filepath.Join(harness, keeperKeyFile), &m.keeperKey},
		{filepath.Join(fat, "ca.crt"), &m.caCert},
		{filepath.Join(fat, "server.crt"), &m.serverCert},
		{filepath.Join(fat, "server.key"), &m.serverKey},
	} {
		if *f.into, err = read(f.path); err != nil {
			return material{}, "", err
		}
	}
	meta, err := config.Dir(d.Config).LoadInstanceMetadata(s.Instance)
	if err != nil {
		return material{}, "", fmt.Errorf("read the rehearsal instance's record: %w", err)
	}
	if meta.Carrier == nil {
		return material{}, "", errors.New("the rehearsal instance's record names no tunnel; start a new rehearsal in a new directory")
	}
	host, _, err := net.SplitHostPort(meta.Carrier.Endpoint)
	if err != nil || host != "127.0.0.1" {
		return material{}, "", fmt.Errorf("the rehearsal instance's record names the tunnel %q, not one on 127.0.0.1", meta.Carrier.Endpoint)
	}
	return m, meta.Carrier.Endpoint, nil
}

func caKeyPath(cfg config.Dir, inst string) string {
	return filepath.Join(cfg.InstancePath(inst), "fatline", "ca.key")
}

func notAfter(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, errors.New("no certificate in the keeper's leaf")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter.UTC(), nil
}

// iniCore is a gcloud configuration file holding an account and a project.
func iniCore(account, project string) string {
	return "[core]\naccount = " + account + "\nproject = " + project + "\n"
}

// writeGCloudConfig writes config_rehearsal for a scenario: the instance's
// account and project, or, in identity-mismatch, another project.
func writeGCloudConfig(s Spec, scenario string) error {
	project := s.Project
	if scenario == ScenarioIdentityMismatch {
		project = mismatchProject
	}
	return writeAtomic(filepath.Join(s.Dirs.GCloud, "configurations", "config_"+gcloudConfigName), []byte(iniCore(s.Account, project)))
}

// kubeconfigYAML has GKE's shape: one cluster, one context, and a user whose
// credential comes from gke-gcloud-auth-plugin, named by bare name.
func kubeconfigYAML(inst string) []byte {
	name := "farcast-" + inst
	return []byte(`apiVersion: v1
kind: Config
clusters:
- name: ` + name + `
  cluster:
    server: https://control-plane.rehearsal.invalid
contexts:
- name: ` + name + `
  context:
    cluster: ` + name + `
    user: ` + name + `
current-context: ` + name + `
users:
- name: ` + name + `
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: gke-gcloud-auth-plugin
      provideClusterInfo: true
      interactiveMode: Never
`)
}

// isMissing reports a path that does not exist.
func isMissing(err error) bool { return errors.Is(err, fs.ErrNotExist) }
