// Package identity is FatLine's operator-side mTLS provisioning surface: it
// mints and assembles the per-instance certificate material that `farcast
// connect` (2.3) needs, without exposing FatLine's internal crypto package.
//
// The trust root is one self-signed CA per instance — the instance's sovereign
// data-plane identity, with no public CA, ACME, or Google IAM in the path
// (ADR 0005). The CA issues an operator client leaf (URI SAN
// farcast://<instance>/operator), a FatLine server leaf (DNS SAN
// <instance>.fatline.farcast, the pinned server name), and later keeper and
// application client leaves. FatLine's public tunnel admits the operator's
// and the keepers' and nothing else. The CA private key is the crown jewel:
// the operator holds it and it is NEVER shipped to the cluster — only the CA
// certificate and the server leaf+key are.
package identity

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
)

// OperatorURI is the SPIFFE-style identity carried in the operator's client
// certificate (a URI SAN), authorized by FatLine's tunnel server.
func OperatorURI(instance string) string {
	return "farcast://" + instance + "/operator"
}

// ServerName is the FatLine server's pinned identity (a DNS SAN). It is a
// synthetic name verified against the per-instance CA — never resolved in
// public DNS — so the certificate is independent of whatever address the
// carrier actually listens on (ADR 0005's carrier-independent server identity).
func ServerName(instance string) string {
	return instance + serverNameSuffix
}

const serverNameSuffix = ".fatline.farcast"

// InstanceFromServerName is ServerName's inverse. It accepts exactly one label
// before the suffix: FatLine reads which instance it serves from its own
// server leaf, and anything looser would let a malformed leaf name a
// different one.
func InstanceFromServerName(name string) (string, bool) {
	inst, ok := strings.CutSuffix(name, serverNameSuffix)
	if !ok || inst == "" || strings.Contains(inst, ".") {
		return "", false
	}
	return inst, true
}

// KeyholderServerName is the DataSphere keyholder's pinned identity (a DNS
// SAN), distinct from FatLine's so that the two are separately verifiable and
// a leaf minted for one cannot stand in for the other.
func KeyholderServerName(instance string) string {
	return instance + ".datasphered.farcast"
}

// KeeperURI is the identity a keeper device presents (phase 5.4). Each device
// is named so that one can be revoked without revoking the fleet.
func KeeperURI(instance, device string) string {
	return "farcast://" + instance + "/keeper/" + device
}

// KeeperBundleURIPrefix starts the URI SAN that binds a keeper's leaf to the
// one bundle it was enrolled with. The keyholder refuses a keeper's push whose
// bundle does not hash to it: a key ID is a label, so without this a leaf
// could push keys of its own making under the IDs the instance pins.
// datasphere/keyholder mirrors it; a test asserts the two agree.
const KeeperBundleURIPrefix = "urn:farcast:keeper-bundle:sha256:"

const keeperBundleDomain = "farcast-keeper-bundle-v1"

// KeeperBundleDigest is the digest a keeper leaf binds: SHA-256 over a domain
// label and the marshalled bundle. It is a function of key material, so it
// rests only on the device beside the bundle and is never written where the
// cloud stores anything.
func KeeperBundleDigest(bundle []byte) string {
	h := sha256.New()
	h.Write([]byte(keeperBundleDomain))
	h.Write(bundle)
	return hex.EncodeToString(h.Sum(nil))
}

// leafTokenDomain separates a leaf token from the leaf's ordinary SHA-256
// fingerprint, so the token cannot be joined against a fingerprint printed
// anywhere else.
const leafTokenDomain = "farcast-leaf-token-v1"

// LeafToken is the opaque name a tunnel peer is attributed by: the first 8
// bytes of SHA-256 over a domain label and the leaf's DER, as 16 hex
// characters.
//
// It names a leaf, not a device, and only the operator's machine can turn it
// back into a device: it records the token when it issues a keeper's leaf, and
// nothing else can recompute it. A leaf's key and serial are random, and the
// tunnel is TLS 1.3 only, so the client certificate travels encrypted and the
// cloud never holds the bytes the token is a function of.
//
// FatLine computes it from the verified leaf and hands it to Shrike's picture,
// read only over the operator's route. It is never written to a log line: a
// stable per-device pseudonym in a provider-ingested log would let the
// provider follow one device across addresses for the leaf's whole life, and
// count the fleet (ADR 0015).
func LeafToken(der []byte) string {
	h := sha256.New()
	h.Write([]byte(leafTokenDomain))
	h.Write(der)
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// LeafTokenPEM is LeafToken over the first certificate in a PEM block — what
// the operator's machine holds when it issues a leaf. It hashes the DER, as
// FatLine does, never the PEM text.
func LeafTokenPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("identity: no certificate in the PEM given")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("identity: parse leaf: %w", err)
	}
	return LeafToken(block.Bytes), nil
}

// AppURI is the identity a deployed application presents to the keyholder's
// data path (ADR 0018 decisions 1 and 6). Namespace and name together, so two
// deployments of one manifest are two principals.
func AppURI(instance, namespace, app string) string {
	return "farcast://" + instance + "/app/" + namespace + "/" + app
}

// DeviceURI is the identity a thin device presents to the data path (ADR 0018
// decision 2): a leaf and no keyring, served storage and never the control
// surface.
func DeviceURI(instance, device string) string {
	return "farcast://" + instance + "/device/" + device
}

// IssueAppClient issues one application's client leaf from an already-minted
// CA.
//
// It is minted at `farcast run`, delivered beside the application's egress
// credential, and rotates by redeploying — the transport-credential class of
// ADR 0010 decision 4 and ADR 0013 decision 8, not the keyring's. The CA key
// is an argument and is never retained.
func IssueAppClient(caCertPEM, caKeyPEM []byte, instance, namespace, app string) (certPEM, keyPEM []byte, err error) {
	if instance == "" || namespace == "" || app == "" {
		return nil, nil, errors.New("identity: an application identity needs an instance, a namespace and a name")
	}
	ca, err := fcrypto.LoadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := ca.IssueClient(AppURI(instance, namespace, app))
	if err != nil {
		return nil, nil, fmt.Errorf("identity: issue application client cert: %w", err)
	}
	return leaf.CertPEM, leaf.KeyPEM, nil
}

// IssueKeyholderServer issues a server leaf for the in-cluster keyholder from
// an already-minted CA.
//
// It exists as a separate issuance rather than a second leaf out of Mint
// because the keyholder is deployed later than the tunnel and may be
// redeployed independently — and because an instance that never uses in-cluster
// storage should never have had this leaf minted at all.
//
// The CA private key is an argument and is never retained: it lives on the
// operator's machine and this function is a pure transformation over it.
func IssueKeyholderServer(caCertPEM, caKeyPEM []byte, instance string) (certPEM, keyPEM []byte, err error) {
	if instance == "" {
		return nil, nil, errors.New("identity: empty instance name")
	}
	ca, err := fcrypto.LoadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := ca.IssueServer(KeyholderServerName(instance))
	if err != nil {
		return nil, nil, err
	}
	return leaf.CertPEM, leaf.KeyPEM, nil
}

// IssueKeeperClient issues one keeper device's client leaf from an
// already-minted CA (phase 5.4).
//
// It is a separate issuance from Mint's operator leaf for the reason the
// keeper design turns on: each device is named, so one can be revoked without
// revoking the fleet, and a device holds a credential that authorizes the seal
// control surface and nothing else.
//
// The CA private key is an argument and is never retained. That is what keeps
// a keeper unable to enrol another keeper: minting happens on the operator's
// machine, and the device receives a leaf rather than the authority to make
// one.
//
// The leaf carries the CA's ordinary 90-day validity, which is the fleet's
// only automatic revocation: a device that is never re-enrolled stops being
// able to re-seed. `keeper revoke` is immediate for the operator's own records
// and bounded by this date in the cluster.
//
// It also binds the bundle the device is given (KeeperBundleURIPrefix), so the
// leaf re-seeds with that bundle and no other: a stolen leaf cannot carry keys
// of its own making, and once a rotation moves the instance's key pin past the
// bundle, the leaf can push nothing at all.
func IssueKeeperClient(caCertPEM, caKeyPEM []byte, instance, device string, bundle []byte) (certPEM, keyPEM []byte, err error) {
	if instance == "" {
		return nil, nil, errors.New("identity: empty instance name")
	}
	if device == "" {
		return nil, nil, errors.New("identity: empty device name")
	}
	if len(bundle) == 0 {
		return nil, nil, errors.New("identity: a keeper leaf binds a bundle, and none was given")
	}
	ca, err := fcrypto.LoadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := ca.IssueClientBinding(KeeperURI(instance, device), KeeperBundleURIPrefix+KeeperBundleDigest(bundle))
	if err != nil {
		return nil, nil, fmt.Errorf("identity: issue keeper client cert: %w", err)
	}
	return leaf.CertPEM, leaf.KeyPEM, nil
}

// Material is a per-instance mTLS identity, PEM-encoded for storage. CAKeyPEM is
// the crown jewel — it stays on the operator's machine; ClusterSecret carries
// only what FatLine needs in-cluster.
type Material struct {
	Instance    string
	ServerName  string
	OperatorURI string

	CACertPEM     []byte
	CAKeyPEM      []byte // never shipped to the cluster
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	ServerCertPEM []byte
	ServerKeyPEM  []byte
}

// Mint creates a fresh per-instance CA and issues the operator client leaf and
// the FatLine server leaf from it.
func Mint(instance string) (*Material, error) {
	if instance == "" {
		return nil, errors.New("identity: empty instance name")
	}
	ca, err := fcrypto.NewCA(instance)
	if err != nil {
		return nil, err
	}
	caKey, err := ca.KeyPEM()
	if err != nil {
		return nil, err
	}
	client, err := ca.IssueClient(OperatorURI(instance))
	if err != nil {
		return nil, fmt.Errorf("identity: issue operator client cert: %w", err)
	}
	server, err := ca.IssueServer(ServerName(instance))
	if err != nil {
		return nil, fmt.Errorf("identity: issue server cert: %w", err)
	}
	return &Material{
		Instance:      instance,
		ServerName:    ServerName(instance),
		OperatorURI:   OperatorURI(instance),
		CACertPEM:     ca.CertPEM,
		CAKeyPEM:      caKey,
		ClientCertPEM: client.CertPEM,
		ClientKeyPEM:  client.KeyPEM,
		ServerCertPEM: server.CertPEM,
		ServerKeyPEM:  server.KeyPEM,
	}, nil
}

// DialTLS returns exactly what tunnel.ClientIdentity needs to dial the instance:
// the operator's client certificate, a verification pool trusting ONLY the
// per-instance CA, and the pinned server name — built from the (possibly
// disk-loaded) CA cert + client leaf, without touching FatLine internals.
func (m *Material) DialTLS() (cert tls.Certificate, caPool *x509.CertPool, serverName string, err error) {
	cert, err = tls.X509KeyPair(m.ClientCertPEM, m.ClientKeyPEM)
	if err != nil {
		return tls.Certificate{}, nil, "", fmt.Errorf("identity: parse client cert: %w", err)
	}
	caPool, err = fcrypto.PoolFromPEM(m.CACertPEM)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	name := m.ServerName
	if name == "" {
		name = ServerName(m.Instance)
	}
	return cert, caPool, name, nil
}
