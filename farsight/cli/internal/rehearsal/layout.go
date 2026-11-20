package rehearsal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
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
	"github.com/sofmon/farcast/farsight/cli/internal/keeper"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/fatline/identity"
)

// The state directory (D3) and the instance record in it (D4).

const (
	// keeperDevice is the one enrolled keeper.
	keeperDevice = "phone"
	// shopNamespace is the one application namespace.
	shopNamespace = "shop"
	callsLog      = "calls.log"
	harnessSubdir = "harness"
)

// The harness's own leaves, written on the first Start and read on a restart.
// writerPubFile is the writer's public key, kept here so a restart registers
// it without reading credentials.yaml, the file the tests prove 'world' never
// opens.
const (
	khCertFile     = "keyholder-server.crt"
	khKeyFile      = "keyholder-server.key"
	keeperCertFile = "keeper-" + keeperDevice + ".crt"
	keeperKeyFile  = "keeper-" + keeperDevice + ".key"
	writerPubFile  = "writer.pub"
)

// The instance's identities in the rehearsal's cluster (ADR 0023 M2.4). The
// reader's email is the loopback form farcast derives for the instance,
// readerName(inst)@rehearsal.invalid; the writer's is a placeholder, and
// every read it makes is refused.
const (
	identityDomain = "rehearsal.invalid"
	writerEmail    = "writer@" + identityDomain
	readerID       = "reader"
	writerID       = "writer"
	// readerDays is how long the reader's certificate, and so its key, lasts:
	// 'farcast reader init's default.
	readerDays = 365
)

// The reader's key in the instance directory (config's names for it), and
// where reader-missing moves it.
const (
	readerKeyFile  = "reader.key"
	readerCertFile = "reader.crt"
	readerAwayFile = "reader.key.away"
	clusterCAFile  = "cluster-ca.crt"
)

// component names, as FatLine's, the kernel's and the keyholder's deploy
// packages name their workloads ('world' finds them by these).
const (
	nameFatLine   = "fatline"
	nameShrike    = "shrike"
	nameKernel    = "technocore"
	nameKeyholder = "datasphered"
)

// errMadeBeforeM24 refuses a directory a harness from before ADR 0023 M2.4
// made: fake tools and a gcloud directory, and no cluster CA.
const errMadeBeforeM24 = "this rehearsal was made before ADR 0023 M2.4 moved its cluster into the harness; start a new one in a new directory"

// material is what a running rig needs, and nothing more: never the CA's
// private key, and never a private key of the reader or the writer.
type material struct {
	caCert                []byte
	serverCert, serverKey []byte // FatLine's
	khCert, khKey         []byte // the keyholders'
	keeperCert, keeperKey []byte // the keeper device's
	readerPub, writerPub  *rsa.PublicKey
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

// readerName is the reader service account's ID farcast derives for an
// instance: "farcast-reader-" and the first 8 hex characters of the name's
// SHA-256. It is the cli package's readerName, which is unexported; the
// rehearsal's end-to-end tests fail if the two ever differ, because farcast
// then refuses the recorded reader.
func readerName(inst string) string {
	sum := sha256.Sum256([]byte(inst))
	return "farcast-reader-" + hex.EncodeToString(sum[:])[:8]
}

// readerEmail is the instance's reader in the rehearsal's cluster.
func readerEmail(inst string) string { return readerName(inst) + "@" + identityDomain }

// makeLayout writes a new rehearsal into root, which exists and is empty. It
// returns the material the servers need, and writes the spec last, so a
// directory a failed Start leaves is never mistaken for a rehearsal.
// cluster-ca.crt is not written here: the cluster writes it each time it
// starts, since every start makes a new CA.
func makeLayout(root string, s Spec, tunnelAddr, clusterAddr string, now time.Time) (material, error) {
	d := s.Dirs
	harness := filepath.Join(root, harnessSubdir)
	if err := os.MkdirAll(harness, 0o700); err != nil {
		return material{}, err
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
	// The keeper is enrolled as a real one is (ADR 0020 decision 3): its key
	// is made for its request, the CA certifies the request's key, and the
	// key exists only here in memory and in harness/keeper-phone.key — never
	// handed to anything that holds the CA key.
	req, err := keeper.GenerateRequest()
	if err != nil {
		return material{}, err
	}
	keeperCert, err := identity.IssueKeeperClient(mint.CACertPEM, mint.CAKeyPEM, inst, keeperDevice, []byte("rehearsal-bundle"), req.RequestDER)
	if err != nil {
		return material{}, err
	}
	keeperKey := req.KeyPEM
	m := material{
		caCert: mint.CACertPEM, serverCert: mint.ServerCertPEM, serverKey: mint.ServerKeyPEM,
		khCert: khCert, khKey: khKey, keeperCert: keeperCert, keeperKey: keeperKey,
	}
	for name, data := range map[string][]byte{khCertFile: khCert, khKeyFile: khKey, keeperCertFile: keeperCert, keeperKeyFile: keeperKey} {
		if err := os.WriteFile(filepath.Join(harness, name), data, 0o600); err != nil {
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

	// The reader (ADR 0023 M2.3), made as 'farcast reader init' makes it: an
	// RSA-2048 key and its certificate. Its key id is 40 hex characters, the
	// shape of Google's, derived from the public key as the tests' are.
	readerKey, readerCert, err := kube.NewReaderKey(rand.Reader, now.Add(-time.Hour), readerDays)
	if err != nil {
		return material{}, err
	}
	if m.readerPub, err = certPublicKey(readerCert); err != nil {
		return material{}, fmt.Errorf("the reader's certificate: %w", err)
	}
	keyID, err := keyIDOf(m.readerPub)
	if err != nil {
		return material{}, err
	}
	if err := cfg.SaveReaderKey(inst, readerKey, readerCert); err != nil {
		return material{}, err
	}
	if err := placeReaderKey(s, s.Scenario); err != nil {
		return material{}, err
	}

	// The writer: a key credentials.yaml holds, registered with the cluster so
	// that a read made with it reaches the handler and is refused there. It
	// exists so the tests can prove 'world' never opens it.
	writer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return material{}, err
	}
	m.writerPub = &writer.PublicKey
	writerDER, err := x509.MarshalPKCS8PrivateKey(writer)
	if err != nil {
		return material{}, err
	}
	writerJSON, err := json.Marshal(map[string]string{
		"type": "service_account", "client_email": writerEmail,
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: writerDER})),
		"token_uri":   "https://" + clusterAddr + "/token",
	})
	if err != nil {
		return material{}, err
	}
	if err := cfg.SaveInstanceCredentials(inst, &config.InstanceCredentials{Provider: "gke", ServiceAccountKey: string(writerJSON)}); err != nil {
		return material{}, err
	}
	writerPub, err := x509.MarshalPKIXPublicKey(m.writerPub)
	if err != nil {
		return material{}, err
	}
	if err := os.WriteFile(filepath.Join(harness, writerPubFile), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: writerPub}), 0o600); err != nil {
		return material{}, err
	}

	// D4.2: the record. Every name in it is a .invalid placeholder. Region
	// is never consulted: a loopback endpoint is classified without it.
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
		Endpoint: clusterAddr, Status: config.InstanceRunning,
		CostLimit: config.CostLimit{Amount: limitUSD, Currency: "USD", Period: "monthly"},
		CreatedAt: now, UpdatedAt: now,
		Reader:       &config.Reader{Email: readerEmail(inst), KeyID: keyID, GrantedAt: now},
		CloudLogging: config.CloudLoggingSystem, FatLineDeployed: true,
		Carrier:  &config.Carrier{Type: "rehearsal", Endpoint: tunnelAddr, ServerName: identity.ServerName(inst)},
		Registry: &config.Registry{Prefix: "registry.rehearsal.invalid/farcast", FatLineDigest: s.Images[nameFatLine]},
		Kernel: &config.Kernel{
			Deployed: true, Applied: true, Image: s.Images[nameKernel], Namespaces: []string{"farcast-system", shopNamespace},
			Limit: limitUSD, Currency: "USD", Period: "monthly",
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

	if err := os.WriteFile(filepath.Join(root, callsLog), nil, 0o600); err != nil {
		return material{}, err
	}
	return m, writeSpec(root, s)
}

// loadLayout reads what a restart needs from a rehearsal a stopped harness
// left: the harness's leaves and the writer's public key, the instance's CA
// certificate and FatLine's leaf, the reader's public key from reader.crt
// (which reader-missing never moves), and the tunnel's and the cluster's
// addresses the record pins. It never opens ca.key, reader.key or
// credentials.yaml, and it issues nothing.
func loadLayout(s Spec) (m material, tunnelAddr, clusterAddr string, err error) {
	d := s.Dirs
	read := func(path string) ([]byte, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		return b, nil
	}
	harness := filepath.Join(d.Root, harnessSubdir)
	cfg := config.Dir(d.Config)
	fat := filepath.Join(cfg.InstancePath(s.Instance), "fatline")
	var writerPub, readerCert []byte
	for _, f := range []struct {
		path string
		into *[]byte
	}{
		{filepath.Join(harness, khCertFile), &m.khCert},
		{filepath.Join(harness, khKeyFile), &m.khKey},
		{filepath.Join(harness, keeperCertFile), &m.keeperCert},
		{filepath.Join(harness, keeperKeyFile), &m.keeperKey},
		{filepath.Join(harness, writerPubFile), &writerPub},
		{filepath.Join(fat, "ca.crt"), &m.caCert},
		{filepath.Join(fat, "server.crt"), &m.serverCert},
		{filepath.Join(fat, "server.key"), &m.serverKey},
		{filepath.Join(cfg.InstancePath(s.Instance), readerCertFile), &readerCert},
	} {
		if *f.into, err = read(f.path); err != nil {
			return material{}, "", "", err
		}
	}
	// A rehearsal made before ADR 0020 has an Ed25519 CA, which FatLine no
	// longer loads. Its scratch data is what a fresh rehearsal recreates, so
	// there is no migration: it is refused, and says so.
	if err := identity.RequireP256CA(m.caCert); err != nil {
		return material{}, "", "", errors.New("this rehearsal was made before ADR 0020 moved the instance PKI to P-256; start a new one in a new directory")
	}
	if m.readerPub, err = certPublicKey(readerCert); err != nil {
		return material{}, "", "", fmt.Errorf("the rehearsal instance's reader.crt: %w", err)
	}
	if m.writerPub, err = publicKey(writerPub); err != nil {
		return material{}, "", "", fmt.Errorf("the harness's %s: %w", writerPubFile, err)
	}
	meta, err := cfg.LoadInstanceMetadata(s.Instance)
	if err != nil {
		return material{}, "", "", fmt.Errorf("read the rehearsal instance's record: %w", err)
	}
	if meta.Carrier == nil {
		return material{}, "", "", errors.New("the rehearsal instance's record names no tunnel; start a new rehearsal in a new directory")
	}
	if !onLoopback(meta.Carrier.Endpoint) {
		return material{}, "", "", fmt.Errorf("the rehearsal instance's record names the tunnel %q, not one on 127.0.0.1", meta.Carrier.Endpoint)
	}
	if !onLoopback(meta.Endpoint) {
		return material{}, "", "", fmt.Errorf("the rehearsal instance's record names the cluster %q, not one on 127.0.0.1", meta.Endpoint)
	}
	return m, meta.Carrier.Endpoint, meta.Endpoint, nil
}

// onLoopback reports whether addr is 127.0.0.1:<port>.
func onLoopback(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	return err == nil && host == "127.0.0.1" && port != ""
}

// madeBeforeM24 reports whether root holds a rehearsal a harness from before
// ADR 0023 M2.4 made: its rehearsal.json, the fake tools' directories or the
// gcloud directory, and no instance with a cluster CA.
func madeBeforeM24(root string) bool {
	if _, err := os.Lstat(filepath.Join(root, specFile)); err != nil {
		return false
	}
	old := false
	for _, p := range []string{filepath.Join("kube", "bin"), filepath.Join("sdk", "bin"), "gcloud"} {
		if _, err := os.Lstat(filepath.Join(root, p)); err == nil {
			old = true
		}
	}
	if !old {
		return false
	}
	cas, err := filepath.Glob(filepath.Join(root, "config", "instances", "*", clusterCAFile))
	return err == nil && len(cas) == 0
}

// placeReaderKey puts the instance's reader key where a scenario wants it:
// aside, as reader.key.away, in reader-missing, and back as reader.key in
// every other. A key already where it belongs is left alone.
func placeReaderKey(s Spec, scenario string) error {
	inst := config.Dir(s.Dirs.Config).InstancePath(s.Instance)
	from, to := filepath.Join(inst, readerAwayFile), filepath.Join(inst, readerKeyFile)
	if scenario == ScenarioReaderMissing {
		from, to = to, from
	}
	if _, err := os.Lstat(from); isMissing(err) {
		return nil
	} else if err != nil {
		return err
	}
	return os.Rename(from, to)
}

// certPublicKey is a PEM certificate's RSA public key.
func certPublicKey(certPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("its key is %T, not RSA", c.PublicKey)
	}
	return pub, nil
}

// publicKey is a PEM PKIX public key, which must be RSA.
func publicKey(pubPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("no public key")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("its key is %T, not RSA", k)
	}
	return pub, nil
}

// keyIDOf is 40 hex characters derived from a public key: the first 20 bytes
// of its SPKI's SHA-256.
func keyIDOf(pub *rsa.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:20]), nil
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

// isMissing reports a path that does not exist.
func isMissing(err error) bool { return errors.Is(err, fs.ErrNotExist) }
