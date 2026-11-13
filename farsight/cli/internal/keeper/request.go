package keeper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/fatline/identity"
)

// A keeper's key is born on the device that keeps (ADR 0020 decision 3). The
// device writes it here, under the same directory rules as everything else a
// keeper holds, and sends the operator a PKCS#10 request for it: the request
// carries the public key and no secret. The operator's machine certifies that
// key and never sees the private half, so the packet that comes back carries a
// certificate and the bundle, and install puts the certificate beside the key
// made here.
const (
	requestKeyFile    = "request.key"  // 0600, PKCS#8 P-256, until install moves it to leaf.key
	requestRecordFile = "request.yaml" // 0600, no key material
)

// KeyStoreFile is a key born as a 0600 file under the keeper directory's rules
// (ADR 0020 decision 3: a desktop keeper). 7.5 adds secure-enclave; ADR 0018
// devices add strongbox, tee, tpm.
const KeyStoreFile = "file"

// requestVersion is the schema of request.yaml.
const requestVersion = 1

// Request is this device's record of a request it made and has not installed
// a certificate for yet. It holds no key material: the key is request.key,
// beside it.
type Request struct {
	Version        int       `yaml:"version"` // 1
	Instance       string    `yaml:"instance"`
	CreatedAt      time.Time `yaml:"created_at"`
	KeySHA256      string    `yaml:"key_sha256"`
	KeyStore       string    `yaml:"key_store"`
	BackupExcluded bool      `yaml:"backup_excluded"`
	BackupNote     string    `yaml:"backup_note,omitempty"`
}

// GeneratedRequest is a fresh P-256 key and the PKCS#10 request for it, in
// memory. KeyPEM is the private key: the caller writes it where it belongs and
// clears it, and prints none of it.
type GeneratedRequest struct {
	KeyPEM, RequestPEM, RequestDER []byte
	KeySHA256                      string
}

// ErrPendingRequest is a request made on this device and not installed yet.
var ErrPendingRequest = errors.New("keeper: a request is already pending on this device")

// generateKey is the only place a keeper key is made. A seam, so a test can
// count calls and prove that nothing is generated before Prepare succeeds.
// Tests that swap it do not run in parallel.
var generateKey = func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// GenerateRequest makes a P-256 key and the request for it from the minimal
// template — an empty subject and no attributes, which is all the operator's
// machine reads of a request anyway (it certifies the key and nothing else) —
// and checks the result the way the operator's machine will, so a request this
// device hands over is one enrolment accepts.
func GenerateRequest() (GeneratedRequest, error) {
	key, err := generateKey()
	if err != nil {
		return GeneratedRequest{}, fmt.Errorf("keeper: make a key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return GeneratedRequest{}, fmt.Errorf("keeper: make the request: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return GeneratedRequest{}, fmt.Errorf("keeper: encode the key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	clear(pkcs8)
	requestPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	parsed, err := identity.ParseRequest(requestPEM)
	if err != nil {
		clear(keyPEM)
		return GeneratedRequest{}, fmt.Errorf("keeper: the request this device made does not pass enrolment's checks: %w", err)
	}
	want, err := identity.KeyFingerprint(&key.PublicKey)
	if err != nil || want != parsed.KeySHA256 {
		clear(keyPEM)
		return GeneratedRequest{}, errors.New("keeper: the request this device made does not carry the key it made")
	}
	return GeneratedRequest{KeyPEM: keyPEM, RequestPEM: requestPEM, RequestDER: parsed.DER, KeySHA256: parsed.KeySHA256}, nil
}

// MaxInstanceLen bounds an instance name, as 'farcast install' does.
const MaxInstanceLen = 32

// ValidateInstance is the CLI's instance-name rule (install's
// validateInstanceName): a lowercase letter first, only lowercase letters,
// digits and dashes, no trailing dash, at most MaxInstanceLen bytes.
//
// It lives here because Install builds a directory path from a packet's
// instance, and 'keeper request' builds one from its argument: a name that
// could climb out of the keepers directory is refused before it is joined
// into a path. The refusal does not repeat the name.
func ValidateInstance(instance string) error {
	if instance == "" {
		return errors.New("keeper: an instance name is required")
	}
	if len(instance) > MaxInstanceLen {
		return fmt.Errorf("keeper: an instance name is at most %d bytes", MaxInstanceLen)
	}
	if instance[0] < 'a' || instance[0] > 'z' {
		return errors.New("keeper: an instance name starts with a lowercase letter")
	}
	for i := 0; i < len(instance); i++ {
		c := instance[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return errors.New("keeper: an instance name uses only lowercase letters, digits and dashes")
		}
	}
	if instance[len(instance)-1] == '-' {
		return errors.New("keeper: an instance name does not end with a dash")
	}
	return nil
}

// Prepare applies a keeper directory's rules to dir: a synced folder is
// refused (never overridable), the directory is made 0700, and it is excluded
// from the platform's backup pipeline — refused unless force when the
// exclusion cannot be read back. It returns what the exclusion check found, to
// be recorded.
//
// Install runs it before it writes, and NewRequest before it makes a key: a
// key born in a directory that fails these rules is a key that already rests
// somewhere it may be copied off the device.
func Prepare(dir string, force bool) (excluded bool, note string, err error) {
	if err := refuseSyncedPath(dir); err != nil {
		// Not overridable. A synced directory is a live upload of the bundle
		// and the key to somebody's cloud, which is the exact outcome this
		// whole design exists to prevent — and unlike a backup pipeline it is
		// continuous.
		return false, "", err
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return false, "", fmt.Errorf("keeper: preparing %s: %w", dir, err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return false, "", fmt.Errorf("keeper: securing %s: %w", dir, err)
	}
	excluded = true
	if err := excludeFromBackup(dir); err != nil {
		excluded, note = false, err.Error()
		if !force {
			return false, note, fmt.Errorf(
				"keeper: %w\n\nThe bundle, this device's private key and the ledger would rest somewhere the platform "+
					"may copy off the device. ADR 0008 says a platform that cannot guarantee the exclusion cannot "+
					"be a keeper.\n\nIf you have arranged the exclusion yourself, re-run with --accept-backup-risk "+
					"and the record will say that you did.", err)
		}
	}
	return excluded, note, nil
}

// NewRequest makes this device a key for instance, in dir, and the request
// that enrols it.
//
// The order is the guarantee: the directory's rules first, then the refusal of
// a pending request (unless replace), and only then the key — so nothing is
// generated for a directory that fails them. The key is written before the
// record, so a crash between the two leaves a key nobody has a request for,
// which the next NewRequest overwrites, and never a record whose key is gone.
func NewRequest(dir, instance string, force, replace bool, now time.Time) (Request, GeneratedRequest, error) {
	if err := ValidateInstance(instance); err != nil {
		return Request{}, GeneratedRequest{}, err
	}
	excluded, note, err := Prepare(dir, force)
	if err != nil {
		return Request{}, GeneratedRequest{}, err
	}
	pending, err := PendingRequest(dir)
	if err != nil {
		return Request{}, GeneratedRequest{}, err
	}
	if pending != nil && !replace {
		return Request{}, GeneratedRequest{}, fmt.Errorf(
			"%w, made %s: carry it to the operator's machine and install the packet it returns, or replace it "+
				"(a packet issued for the one replaced is then refused here)",
			ErrPendingRequest, pending.CreatedAt.UTC().Format("2006-01-02 15:04 MST"))
	}

	gen, err := GenerateRequest()
	if err != nil {
		return Request{}, GeneratedRequest{}, err
	}
	if err := writeSecret(filepath.Join(dir, requestKeyFile), gen.KeyPEM); err != nil {
		clear(gen.KeyPEM)
		return Request{}, GeneratedRequest{}, err
	}
	rec := Request{
		Version: requestVersion, Instance: instance, CreatedAt: now.UTC(),
		KeySHA256: gen.KeySHA256, KeyStore: KeyStoreFile,
		BackupExcluded: excluded, BackupNote: note,
	}
	out, err := yaml.Marshal(rec)
	if err != nil {
		clear(gen.KeyPEM)
		return Request{}, GeneratedRequest{}, fmt.Errorf("keeper: encode the request record: %w", err)
	}
	if err := writeSecret(filepath.Join(dir, requestRecordFile), out); err != nil {
		clear(gen.KeyPEM)
		return Request{}, GeneratedRequest{}, err
	}
	return rec, gen, nil
}

// PendingRequest reads this device's pending request record in dir: (nil, nil)
// when there is none.
func PendingRequest(dir string) (*Request, error) {
	data, err := os.ReadFile(filepath.Join(dir, requestRecordFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("keeper: reading the request record: %w", err)
	}
	var r Request
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, errors.New("keeper: the request record did not decode")
	}
	return &r, nil
}

// DiscardRequest removes a pending request: its key and its record. It is
// idempotent, and leaves an installed keeper's material alone.
func DiscardRequest(dir string) error {
	for _, f := range []string{requestKeyFile, requestRecordFile} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("keeper: removing %s: %w", f, err)
		}
	}
	return nil
}

// ForeignKeyError is install's security event: a packet whose certificate
// certifies a key this device does not hold.
//
// It is never a mistake to shrug off. Either the packet is for another device,
// or the request this device made was replaced on its way to the operator and
// the operator certified somebody else's key under this device's name — which
// the fingerprint confirmation exists to stop, and which then did not.
type ForeignKeyError struct {
	Instance, Device string
	CertKey          string // fingerprint the certificate certifies
	Pending          string // this device's pending request key, "" when none
	Installed        string // this device's installed leaf key, "" when none
}

func (e *ForeignKeyError) Error() string {
	held := "none"
	switch {
	case e.Pending != "" && e.Installed != "":
		held = "pending request " + identity.FormatFingerprint(e.Pending) + "; installed " + identity.FormatFingerprint(e.Installed)
	case e.Pending != "":
		held = "pending request " + identity.FormatFingerprint(e.Pending)
	case e.Installed != "":
		held = "installed " + identity.FormatFingerprint(e.Installed)
	}
	return fmt.Sprintf("security event: the certificate in this packet certifies key %s, which this device does not hold "+
		"(its key for %s: %s). Nothing was installed. If this is the device that ran 'farcast keeper request %s', "+
		"the leaf was issued to someone else's key: on the operator's machine run 'farcast keeper revoke %s %s', "+
		"rotate ('farcast storage key rotate %s', then 'farcast storage key rekey %s'), and enrol this device again "+
		"from a new request. If it is not, install the packet on the device that made the request.",
		identity.FormatFingerprint(e.CertKey), e.Instance, held, e.Instance, e.Instance, e.Device, e.Instance, e.Instance)
}

// heldKeyFingerprint is the fingerprint of the P-256 key in a PKCS#8 file in
// dir: "" when the file does not exist. The key is parsed only to compute its
// public half's fingerprint, and its bytes are cleared.
func heldKeyFingerprint(dir, name string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("keeper: reading %s: %w", name, err)
	}
	defer clear(data)
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return "", fmt.Errorf("keeper: %s holds no PKCS#8 key", name)
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("keeper: %s does not parse", name)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("keeper: %s is not an ECDSA key", name)
	}
	return identity.KeyFingerprint(&key.PublicKey)
}
