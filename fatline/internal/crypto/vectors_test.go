package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"
)

// ADR 0020's conformance vectors (ADR 0021 decision 7): a P-256 PKI fixture,
// enrolment request vectors and the leaf-token vector, written to
// testdata/pki/ and consumed by every client's tests — FarSightKit copies
// them byte for byte (check.sh 7a), and its regression serves them through
// FatLine's own ServerTLSConfig.
//
// Every input is fixed: keys come from labels, times and serials are
// constants, and every ECDSA signature is RFC 6979 (rand nil), so the files
// regenerate byte for byte. The P-256 fixture comes from the production
// seams (newCAWith, issueFor), so a change to the CA or leaf template changes
// the bytes and fails here first. A deliberate change is made with:
//
//	FARCAST_UPDATE_VECTORS=1 go test -mod=vendor ./fatline/internal/crypto/ -run Vector
//
// then reviewed, and recopied into FarSightKit (farsight/client/apple/README.md).
//
// Helpers that fatline/identity owns (ServerName, OperatorURI,
// KeeperBundleURIPrefix, LeafToken's label) are literals here, because
// identity imports this package; identity_test.go cross-checks each literal
// against the files.

const (
	updateVectorsEnv = "FARCAST_UPDATE_VECTORS"
	vectorDir        = "testdata/pki"
	vectorSchema     = 1

	vectorInstance    = "fixture"
	vectorServerName  = "fixture.fatline.farcast"           // identity.ServerName("fixture")
	vectorOperatorURI = "farcast://fixture/operator"        // identity.OperatorURI("fixture")
	vectorBundlePref  = "urn:farcast:keeper-bundle:sha256:" // identity.KeeperBundleURIPrefix
	vectorTokenLabel  = "farcast-leaf-token-v2"             // identity's leafTokenDomain

	// requestSearchBound bounds the search for the six valid request shapes.
	// Each rare shape (r or s of 31 bytes or fewer) turns up about once in
	// 500 keys.
	requestSearchBound = 100000
)

var (
	vectorIssuedAt = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	vectorVerifyAt = vectorIssuedAt.Add(24 * time.Hour)
)

// vectorFileNames are the five files, and the only files, in testdata/pki.
var vectorFileNames = []string{"p256.json", "foreign.json", "ed25519.json", "requests.json", "token.json"}

// validRequestNames is the pinned order of the six template-shaped requests.
var validRequestNames = []string{"plain", "r_padded", "s_padded", "both_padded", "r_short", "s_short"}

// ---- deterministic inputs (C1) ----

func vectorLabel(label string) []byte { return []byte("farcast-vector-key/" + label) }

// vectorP256 derives a P-256 key from label: d is SHA-256 of
// "farcast-vector-key/<label>/<i>" for the first i the curve accepts.
func vectorP256(label string) *ecdsa.PrivateKey {
	for i := 0; ; i++ {
		d := sha256.Sum256([]byte("farcast-vector-key/" + label + "/" + strconv.Itoa(i)))
		if k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:]); err == nil {
			return k
		}
	}
}

// vectorP384 is vectorP256 on P-384, with SHA-384.
func vectorP384(label string) *ecdsa.PrivateKey {
	for i := 0; ; i++ {
		d := sha512.Sum384([]byte("farcast-vector-key/" + label + "/" + strconv.Itoa(i)))
		if k, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), d[:]); err == nil {
			return k
		}
	}
}

func vectorEd25519(label string) ed25519.PrivateKey {
	seed := sha256.Sum256(vectorLabel(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// vectorRSA builds a 2048-bit RSA key from deterministic probable primes:
// rsa.GenerateKey ignores its reader, and a committed key file would break
// regenerate-and-compare.
func vectorRSA(label string) (*rsa.PrivateKey, error) {
	prime := func(which string) *big.Int {
		for i := 0; ; i++ {
			h1 := sha512.Sum512([]byte("farcast-vector-key/" + label + "/" + which + "/" + strconv.Itoa(i)))
			h2 := sha512.Sum512(h1[:])
			b := append(h1[:], h2[:]...) // 1024 bits
			b[0] |= 0xc0                 // top two bits: p·q has 2048
			b[len(b)-1] |= 1
			if p := new(big.Int).SetBytes(b); p.ProbablyPrime(32) {
				return p
			}
		}
	}
	p, q := prime("p"), prime("q")
	one := big.NewInt(1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	e := big.NewInt(65537)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, errors.New("vector RSA: e is not invertible for these primes")
	}
	k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537}, D: d, Primes: []*big.Int{p, q}}
	k.Precompute()
	if err := k.Validate(); err != nil {
		return nil, fmt.Errorf("vector RSA: %w", err)
	}
	if k.N.BitLen() != 2048 {
		return nil, fmt.Errorf("vector RSA: %d bits, want 2048", k.N.BitLen())
	}
	return k, nil
}

// vectorMLDSA44 (mldsa_vector_test.go) is the ML-DSA-44 key: crypto/mldsa
// needs Go 1.27, and this module's language version is 1.26.

func vectorIssuance(serial int64) issuance {
	return issuance{now: vectorIssuedAt, serial: big.NewInt(serial), rand: nil}
}

// ---- file shapes (design 1.3) ----

type vectorPart struct {
	Identity  string `json:"identity,omitempty"`
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem,omitempty"`
	KeySHA256 string `json:"key_sha256,omitempty"`
}

type vectorPKI struct {
	Schema     int         `json:"schema"`
	About      string      `json:"about"`
	Instance   string      `json:"instance,omitempty"`
	ServerName string      `json:"server_name"`
	IssuedAt   string      `json:"issued_at"`
	VerifyAt   string      `json:"verify_at"`
	CA         vectorPart  `json:"ca"`
	Server     vectorPart  `json:"server"`
	Client     *vectorPart `json:"client,omitempty"`
}

type vectorValidRequest struct {
	Name         string `json:"name"`
	RequestPEM   string `json:"request_pem"`
	KeySHA256    string `json:"key_sha256"`
	PointHex     string `json:"point_hex"`
	TBSHex       string `json:"tbs_hex"`
	SignatureHex string `json:"signature_hex"`
	RBytes       int    `json:"r_bytes"`
	SBytes       int    `json:"s_bytes"`
	HighS        bool   `json:"high_s"`
}

type vectorKeyOnlyRequest struct {
	Name       string `json:"name"`
	RequestPEM string `json:"request_pem"`
	KeySHA256  string `json:"key_sha256"`
}

type vectorInvalidRequest struct {
	Name       string `json:"name"`
	RequestPEM string `json:"request_pem"`
	Refusal    string `json:"refusal"`
}

type vectorRequests struct {
	Schema  int                    `json:"schema"`
	About   string                 `json:"about"`
	Valid   []vectorValidRequest   `json:"valid"`
	KeyOnly vectorKeyOnlyRequest   `json:"key_only"`
	Invalid []vectorInvalidRequest `json:"invalid"`
}

type vectorToken struct {
	Schema  int    `json:"schema"`
	About   string `json:"about"`
	Label   string `json:"label"`
	LeafPEM string `json:"leaf_pem"`
	TwinPEM string `json:"twin_pem"`
	Token   string `json:"token"`
}

// ---- generation ----

// pkiVectors builds all five files from fixed inputs.
func pkiVectors() (map[string][]byte, error) {
	files := map[string][]byte{}
	put := func(name string, v any) error {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		files[name] = append(b, '\n')
		return nil
	}

	p256, clientDER, err := p256Vector()
	if err != nil {
		return nil, fmt.Errorf("p256.json: %w", err)
	}
	foreign, err := foreignVector()
	if err != nil {
		return nil, fmt.Errorf("foreign.json: %w", err)
	}
	ed, err := ed25519Vector()
	if err != nil {
		return nil, fmt.Errorf("ed25519.json: %w", err)
	}
	reqs, err := requestVectors(clientDER)
	if err != nil {
		return nil, fmt.Errorf("requests.json: %w", err)
	}
	tok, err := tokenVector(p256)
	if err != nil {
		return nil, fmt.Errorf("token.json: %w", err)
	}
	for name, v := range map[string]any{
		"p256.json": p256, "foreign.json": foreign, "ed25519.json": ed,
		"requests.json": reqs, "token.json": tok,
	} {
		if err := put(name, v); err != nil {
			return nil, err
		}
	}
	return files, nil
}

func pemString(typ string, der []byte) string { return string(pemEncode(typ, der)) }

func keyPart(identity string, certDER []byte, key crypto.Signer) (vectorPart, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return vectorPart{}, err
	}
	fp, err := KeyFingerprint(key.Public())
	if err != nil {
		return vectorPart{}, err
	}
	return vectorPart{Identity: identity, CertPEM: pemString("CERTIFICATE", certDER), KeyPEM: pemString("PRIVATE KEY", keyDER), KeySHA256: fp}, nil
}

func caPart(ca *CA) (vectorPart, error) {
	fp, err := KeyFingerprint(ca.Cert.PublicKey)
	if err != nil {
		return vectorPart{}, err
	}
	return vectorPart{CertPEM: string(ca.CertPEM), KeySHA256: fp}, nil
}

// p256Vector is what crypto.go issues for the instance "fixture" at
// vectorIssuedAt, through its own issuers. It also returns the client leaf's
// DER for not_a_request.
func p256Vector() (vectorPKI, []byte, error) {
	ca, err := newCAWith(vectorInstance, vectorP256("ca"), vectorIssuance(1))
	if err != nil {
		return vectorPKI{}, nil, err
	}
	serverKey, clientKey := vectorP256("server"), vectorP256("client")
	serverDER, err := ca.issueFor(&serverKey.PublicKey, vectorServerName, x509.ExtKeyUsageServerAuth, nil, vectorIssuance(2))
	if err != nil {
		return vectorPKI{}, nil, err
	}
	clientDER, err := ca.issueFor(&clientKey.PublicKey, vectorOperatorURI, x509.ExtKeyUsageClientAuth, nil, vectorIssuance(3))
	if err != nil {
		return vectorPKI{}, nil, err
	}
	v := vectorPKI{
		Schema:     vectorSchema,
		About:      "ADR 0020's conformance fixture: what crypto.go issues for the instance \"fixture\" at issued_at, through its own issuers. Test data; trusted nowhere else.",
		Instance:   vectorInstance,
		ServerName: vectorServerName,
		IssuedAt:   vectorIssuedAt.Format(time.RFC3339),
		VerifyAt:   vectorVerifyAt.Format(time.RFC3339),
	}
	if v.CA, err = caPart(ca); err != nil {
		return vectorPKI{}, nil, err
	}
	if v.Server, err = keyPart(vectorServerName, serverDER, serverKey); err != nil {
		return vectorPKI{}, nil, err
	}
	client, err := keyPart(vectorOperatorURI, clientDER, clientKey)
	if err != nil {
		return vectorPKI{}, nil, err
	}
	v.Client = &client
	return v, clientDER, nil
}

// foreignVector is another P-256 CA with the same subject as the fixture's,
// issuing a server leaf for the same name: what a pinned trust must refuse.
func foreignVector() (vectorPKI, error) {
	ca, err := newCAWith(vectorInstance, vectorP256("foreign-ca"), vectorIssuance(1))
	if err != nil {
		return vectorPKI{}, err
	}
	serverKey := vectorP256("foreign-server")
	serverDER, err := ca.issueFor(&serverKey.PublicKey, vectorServerName, x509.ExtKeyUsageServerAuth, nil, vectorIssuance(2))
	if err != nil {
		return vectorPKI{}, err
	}
	v := vectorPKI{
		Schema:     vectorSchema,
		About:      "ADR 0020's foreign-CA fixture: another ECDSA P-256 CA with the fixture CA's subject, issuing a server leaf for the fixture's server name. A client that pins the fixture CA must refuse it. Test data; trusted nowhere else.",
		ServerName: vectorServerName,
		IssuedAt:   vectorIssuedAt.Format(time.RFC3339),
		VerifyAt:   vectorVerifyAt.Format(time.RFC3339),
	}
	if v.CA, err = caPart(ca); err != nil {
		return vectorPKI{}, err
	}
	if v.Server, err = keyPart(vectorServerName, serverDER, serverKey); err != nil {
		return vectorPKI{}, err
	}
	return v, nil
}

// ed25519Vector is the PKI ADR 0020 retired, for the negative tests: the
// production templates over Ed25519 keys, signed here because crypto.go
// refuses to issue or load Ed25519. No key_sha256 fields.
func ed25519Vector() (vectorPKI, error) {
	caKey, serverKey := vectorEd25519("ed25519-ca"), vectorEd25519("ed25519-server")
	caTmpl := caTemplate(vectorInstance, vectorIssuance(1))
	caDER, err := x509.CreateCertificate(nil, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		return vectorPKI{}, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return vectorPKI{}, err
	}
	serverDER, err := x509.CreateCertificate(nil, leafTemplate(vectorServerName, x509.ExtKeyUsageServerAuth, nil, vectorIssuance(2)), caCert, serverKey.Public(), caKey)
	if err != nil {
		return vectorPKI{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return vectorPKI{}, err
	}
	return vectorPKI{
		Schema:     vectorSchema,
		About:      "The Ed25519 PKI ADR 0020 retired, in the shapes crypto.go issued before it: a CA and a server leaf for the fixture's server name. For negative tests only: Apple's TLS stacks cannot complete a handshake with it. Test data; trusted nowhere else.",
		ServerName: vectorServerName,
		IssuedAt:   vectorIssuedAt.Format(time.RFC3339),
		VerifyAt:   vectorVerifyAt.Format(time.RFC3339),
		CA:         vectorPart{CertPEM: pemString("CERTIFICATE", caDER)},
		Server:     vectorPart{Identity: vectorServerName, CertPEM: pemString("CERTIFICATE", serverDER), KeyPEM: pemString("PRIVATE KEY", keyDER)},
	}, nil
}

// The raw shapes of a signed request or certificate and of an ECDSA
// signature, for the vectors that take one apart or re-encode it.
type signedRaw struct {
	TBS asn1.RawValue
	Alg asn1.RawValue
	Sig asn1.BitString
}

type ecdsaSig struct{ R, S *big.Int }

// signatureShape reads an ECDSA signature's r and s INTEGER content lengths
// and whether s is in the upper half of the group order.
func signatureShape(sig []byte) (rBytes, sBytes int, highS bool, err error) {
	var raw struct{ R, S asn1.RawValue }
	if rest, err := asn1.Unmarshal(sig, &raw); err != nil || len(rest) != 0 {
		return 0, 0, false, fmt.Errorf("signature: %v", err)
	}
	var s ecdsaSig
	if _, err := asn1.Unmarshal(sig, &s); err != nil {
		return 0, 0, false, err
	}
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	return len(raw.R.Bytes), len(raw.S.Bytes), s.S.Cmp(half) > 0, nil
}

// templateTBSPrefix starts the minimal request template's body: SEQUENCE of 98
// bytes, version 0, an empty subject, and a 91-byte SubjectPublicKeyInfo.
var templateTBSPrefix = []byte{0x30, 0x62, 0x02, 0x01, 0x00, 0x30, 0x00, 0x30, 0x59}

// templateRequest rebuilds a minimal-template request from its point and
// signature, byte by byte as a client without an ASN.1 library does (ADR 0020
// decision 3), so the test proves every valid vector is template-shaped.
func templateRequest(point, sig []byte) []byte {
	spkiAlg := []byte{0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	tbs := slices.Concat(templateTBSPrefix, spkiAlg, []byte{0x03, 0x42, 0x00}, point, []byte{0xa0, 0x00})
	sigAlg := []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}
	bitString := slices.Concat([]byte{0x03, byte(len(sig) + 1), 0x00}, sig)
	body := slices.Concat(tbs, sigAlg, bitString)
	return slices.Concat([]byte{0x30, 0x81, byte(len(body))}, body)
}

func requestVectors(clientCertDER []byte) (vectorRequests, error) {
	out := vectorRequests{
		Schema: vectorSchema,
		About:  "ADR 0020 decision 3's enrolment request vectors. valid: six requests in the minimal template (empty subject, no attributes), one per signature encoding a client's template builder must produce — r or s padded with 0x00, or shorter than 32 bytes. key_only: a valid request that is not the template; issuance must honour its key and nothing else. invalid: each refused by exactly one check, named in refusal. Test data; trusted nowhere else.",
	}

	// valid: the first key whose request has each shape, in the pinned order.
	byName := map[string]vectorValidRequest{}
	shapes := map[string]func(r, s int, high bool) bool{
		"plain":       func(r, s int, high bool) bool { return r == 32 && s == 32 && !high },
		"r_padded":    func(r, s int, _ bool) bool { return r == 33 && s == 32 },
		"s_padded":    func(r, s int, _ bool) bool { return r == 32 && s == 33 },
		"both_padded": func(r, s int, _ bool) bool { return r == 33 && s == 33 },
		"r_short":     func(r, _ int, _ bool) bool { return r <= 31 },
		"s_short":     func(_, s int, _ bool) bool { return s <= 31 },
	}
	var plainDER []byte
	for i := 0; i < requestSearchBound && len(byName) < len(validRequestNames); i++ {
		key := vectorP256("request-" + strconv.Itoa(i))
		der, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{}, key)
		if err != nil {
			return out, err
		}
		var raw signedRaw
		if _, err := asn1.Unmarshal(der, &raw); err != nil {
			return out, err
		}
		r, s, high, err := signatureShape(raw.Sig.Bytes)
		if err != nil {
			return out, err
		}
		for _, name := range validRequestNames {
			if _, filled := byName[name]; filled || !shapes[name](r, s, high) {
				continue
			}
			point, err := key.PublicKey.Bytes()
			if err != nil {
				return out, err
			}
			fp, err := KeyFingerprint(&key.PublicKey)
			if err != nil {
				return out, err
			}
			byName[name] = vectorValidRequest{
				Name: name, RequestPEM: pemString("CERTIFICATE REQUEST", der), KeySHA256: fp,
				PointHex: hex.EncodeToString(point), TBSHex: hex.EncodeToString(raw.TBS.FullBytes),
				SignatureHex: hex.EncodeToString(raw.Sig.Bytes), RBytes: r, SBytes: s, HighS: high,
			}
			if name == "plain" {
				plainDER = der
			}
			break
		}
	}
	for _, name := range validRequestNames {
		v, ok := byName[name]
		if !ok {
			return out, fmt.Errorf("no %s request in the first %d keys", name, requestSearchBound)
		}
		out.Valid = append(out.Valid, v)
	}

	// key_only: a valid request that asks for everything issuance must ignore.
	keyOnly, err := extensionsIgnoredRequest()
	if err != nil {
		return out, err
	}
	out.KeyOnly = keyOnly

	// invalid, in the pinned order.
	add := func(name, refusal string, der []byte) {
		out.Invalid = append(out.Invalid, vectorInvalidRequest{Name: name, RequestPEM: pemString("CERTIFICATE REQUEST", der), Refusal: refusal})
	}
	minimal := func(key crypto.Signer, alg x509.SignatureAlgorithm) ([]byte, error) {
		return x509.CreateCertificateRequest(nil, &x509.CertificateRequest{SignatureAlgorithm: alg}, key)
	}
	rsaKey, err := vectorRSA("request-rsa")
	if err != nil {
		return out, err
	}
	mlKey, err := newVectorMLDSA44("request-mldsa44")
	if err != nil {
		return out, err
	}
	for _, c := range []struct {
		name, refusal string
		key           crypto.Signer
		alg           x509.SignatureAlgorithm
	}{
		{"ed25519_key", RefusalKeyAlgorithm, vectorEd25519("request-ed25519"), 0},
		{"rsa_key", RefusalKeyAlgorithm, rsaKey, 0},
		{"mldsa44_key", RefusalKeyAlgorithm, mlKey, 0},
		{"p384_key", RefusalCurve, vectorP384("request-p384"), x509.ECDSAWithSHA256},
		{"ecdsa_sha1", RefusalSignatureAlgorithm, vectorP256("request-sha1"), x509.ECDSAWithSHA1},
		{"ecdsa_sha384", RefusalSignatureAlgorithm, vectorP256("request-sha384"), x509.ECDSAWithSHA384},
	} {
		der, err := minimal(c.key, c.alg)
		if err != nil {
			return out, fmt.Errorf("%s: %w", c.name, err)
		}
		add(c.name, c.refusal, der)
	}
	bad, err := reSigned(plainDER, func(s *big.Int) *big.Int { return new(big.Int).Add(s, big.NewInt(1)) })
	if err != nil {
		return out, fmt.Errorf("bad_signature: %w", err)
	}
	add("bad_signature", RefusalSignature, bad)
	compressed, err := compressedPointRequest(vectorP256("request-compressed"))
	if err != nil {
		return out, fmt.Errorf("compressed_point: %w", err)
	}
	add("compressed_point", RefusalMalformed, compressed)
	add("trailing_data", RefusalMalformed, append(slices.Clone(plainDER), 0x00))
	add("not_a_request", RefusalMalformed, clientCertDER)
	return out, nil
}

// extensionsIgnoredRequest asks for a subject, a DNS SAN, two URI SANs and
// the extensions of a CA — serverAuth, CA:TRUE, keyCertSign and a validity of
// its own choosing (privateKeyUsagePeriod) — none of which issuance may honour.
func extensionsIgnoredRequest() (vectorKeyOnlyRequest, error) {
	key := vectorP256("request-extensions")
	operator, _ := url.Parse(vectorOperatorURI)
	bundle, _ := url.Parse(vectorBundlePref + "0000000000000000000000000000000000000000000000000000000000000000")
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}})
	if err != nil {
		return vectorKeyOnlyRequest{}, err
	}
	basic, err := asn1.Marshal(struct{ IsCA bool }{true})
	if err != nil {
		return vectorKeyOnlyRequest{}, err
	}
	keyUsage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x04}, BitLength: 6}) // keyCertSign
	if err != nil {
		return vectorKeyOnlyRequest{}, err
	}
	period, err := asn1.Marshal(struct {
		NotBefore time.Time `asn1:"generalized,tag:0,optional"`
		NotAfter  time.Time `asn1:"generalized,tag:1,optional"`
	}{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2046, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		return vectorKeyOnlyRequest{}, err
	}
	der, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: vectorOperatorURI},
		DNSNames: []string{vectorServerName},
		URIs:     []*url.URL{operator, bundle},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: eku},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: basic},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: keyUsage},
			{Id: oidPrivateKeyUsagePeriod, Value: period},
		},
	}, key)
	if err != nil {
		return vectorKeyOnlyRequest{}, err
	}
	fp, err := KeyFingerprint(&key.PublicKey)
	if err != nil {
		return vectorKeyOnlyRequest{}, err
	}
	return vectorKeyOnlyRequest{Name: "extensions_ignored", RequestPEM: pemString("CERTIFICATE REQUEST", der), KeySHA256: fp}, nil
}

var oidPrivateKeyUsagePeriod = asn1.ObjectIdentifier{2, 5, 29, 16}

// reSigned re-encodes a signed request or certificate with its ECDSA s
// replaced by f(s), leaving the signed body and algorithm byte for byte.
func reSigned(der []byte, f func(s *big.Int) *big.Int) ([]byte, error) {
	var raw signedRaw
	if rest, err := asn1.Unmarshal(der, &raw); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("unmarshal: %v", err)
	}
	var sig ecdsaSig
	if _, err := asn1.Unmarshal(raw.Sig.Bytes, &sig); err != nil {
		return nil, err
	}
	sigDER, err := asn1.Marshal(ecdsaSig{R: sig.R, S: f(sig.S)})
	if err != nil {
		return nil, err
	}
	raw.Sig = asn1.BitString{Bytes: sigDER, BitLength: 8 * len(sigDER)}
	return asn1.Marshal(raw)
}

// compressedPointRequest is a request whose SubjectPublicKeyInfo holds the
// compressed form of a P-256 point, correctly signed: Go's parser refuses it
// before any check of ours runs.
func compressedPointRequest(key *ecdsa.PrivateKey) ([]byte, error) {
	point, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	compressed := make([]byte, 33)
	compressed[0] = 0x02 | point[64]&1 // the parity of Y
	copy(compressed[1:], point[1:33])
	params, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	if err != nil {
		return nil, err
	}
	type spki struct {
		Alg pkix.AlgorithmIdentifier
		Key asn1.BitString
	}
	tbs, err := asn1.Marshal(struct {
		Version int
		Subject asn1.RawValue
		SPKI    spki
		Attrs   asn1.RawValue
	}{
		Subject: asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
		SPKI: spki{
			Alg: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, Parameters: asn1.RawValue{FullBytes: params}},
			Key: asn1.BitString{Bytes: compressed, BitLength: 8 * len(compressed)},
		},
		Attrs: asn1.RawValue{FullBytes: []byte{0xa0, 0x00}},
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(tbs)
	sig, err := key.Sign(nil, digest[:], crypto.SHA256) // RFC 6979
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(signedRaw{
		TBS: asn1.RawValue{FullBytes: tbs},
		Alg: asn1.RawValue{FullBytes: []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}},
		Sig: asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)},
	})
}

// vectorTokenOf is LeafToken's v2 recipe, written out here because the
// identity package imports this one (A-T11 ties identity.LeafToken to the
// file).
func vectorTokenOf(label string, cert *x509.Certificate) string {
	sum := sha256.Sum256(slices.Concat([]byte(label), cert.RawTBSCertificate))
	return hex.EncodeToString(sum[:8])
}

// tokenVector is the fixture's client leaf and its twin — the same
// certificate with its signature re-encoded as s' = n - s, which verifies as
// well — and the one token both must yield (ADR 0020 decision 4).
func tokenVector(p256 vectorPKI) (vectorToken, error) {
	leafDER, err := pemDER(p256.Client.CertPEM, "CERTIFICATE")
	if err != nil {
		return vectorToken{}, err
	}
	n := elliptic.P256().Params().N
	twinDER, err := reSigned(leafDER, func(s *big.Int) *big.Int { return new(big.Int).Sub(n, s) })
	if err != nil {
		return vectorToken{}, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return vectorToken{}, err
	}
	return vectorToken{
		Schema:  vectorSchema,
		About:   "ADR 0020 decision 4's leaf-token vector: the fixture's client leaf, its twin (the same certificate with the signature re-encoded as s' = n - s, which verifies as well), and the one token both yield: the first 8 bytes of SHA-256 over label and the leaf's RawTBSCertificate, in hex. Test data; trusted nowhere else.",
		Label:   vectorTokenLabel,
		LeafPEM: p256.Client.CertPEM,
		TwinPEM: pemString("CERTIFICATE", twinDER),
		Token:   vectorTokenOf(vectorTokenLabel, leaf),
	}, nil
}

func pemDER(s, typ string) ([]byte, error) {
	block, rest := pem.Decode([]byte(s))
	if block == nil || block.Type != typ || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("not one %s PEM block", typ)
	}
	return block.Bytes, nil
}

// ---- tests ----

// readVector decodes a committed vector file.
func readVector(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatalf("read %s: %v (run with %s=1 to write it)", name, err, updateVectorsEnv)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

func mustCert(t *testing.T, s string) *x509.Certificate {
	t.Helper()
	der, err := pemDER(s, "CERTIFICATE")
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A-T8. The five files regenerate byte for byte, equal what is committed,
// and hold what the fixture claims.
func TestPKIVectors(t *testing.T) {
	first, err := pkiVectors()
	if err != nil {
		t.Fatal(err)
	}
	again, err := pkiVectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(vectorFileNames) {
		t.Fatalf("%d files generated, want %d", len(first), len(vectorFileNames))
	}
	for _, name := range vectorFileNames {
		if !bytes.Equal(first[name], again[name]) {
			t.Fatalf("%s: two generations from the same inputs differ", name)
		}
	}

	if os.Getenv(updateVectorsEnv) != "" {
		if err := os.MkdirAll(vectorDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range vectorFileNames {
			if err := os.WriteFile(filepath.Join(vectorDir, name), first[name], 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	entries, err := os.ReadDir(vectorDir)
	if err != nil {
		t.Fatalf("read %s: %v (run with %s=1 to write it)", vectorDir, err, updateVectorsEnv)
	}
	var present []string
	for _, e := range entries {
		present = append(present, e.Name())
	}
	if want := slices.Sorted(slices.Values(vectorFileNames)); !slices.Equal(present, want) {
		t.Errorf("%s holds %v, want exactly %v", vectorDir, present, want)
	}
	for _, name := range vectorFileNames {
		committed, err := os.ReadFile(filepath.Join(vectorDir, name))
		if err != nil {
			t.Fatalf("read %s: %v (run with %s=1 to write it)", name, err, updateVectorsEnv)
		}
		if !bytes.Equal(committed, first[name]) {
			t.Errorf("%s differs from what crypto.go now issues. If the change is deliberate, rerun with %s=1, review the diff and recopy it into FarSightKit.", name, updateVectorsEnv)
		}
	}

	t.Run("p256", func(t *testing.T) { checkP256Fixture(t, first["p256.json"]) })
	t.Run("foreign", func(t *testing.T) { checkForeignFixture(t, first["foreign.json"], first["p256.json"]) })
	t.Run("ed25519", func(t *testing.T) { checkEd25519Fixture(t, first["ed25519.json"]) })
	t.Run("requests", func(t *testing.T) { checkRequestShapes(t, first["requests.json"]) })
	t.Run("token", func(t *testing.T) { checkTokenVector(t, first["token.json"], first["p256.json"]) })
}

func decodeVector(t *testing.T, b []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatal(err)
	}
}

// requireP256SHA256 holds a certificate to decision 1.
func requireP256SHA256(t *testing.T, what string, c *x509.Certificate) {
	t.Helper()
	if !IsP256(c.PublicKey) {
		t.Errorf("%s: key is %s, want ECDSA P-256", what, keyName(c.PublicKey))
	}
	if c.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("%s: signed %v, want ECDSA-SHA256", what, c.SignatureAlgorithm)
	}
}

// sameShape compares two certificates on everything but serial, times, keys
// and the key identifiers derived from them.
func sameShape(t *testing.T, what string, got, want *x509.Certificate) {
	t.Helper()
	type shape struct {
		Subject, Issuer        string
		KeyUsage               x509.KeyUsage
		ExtKeyUsage            []x509.ExtKeyUsage
		UnknownExtKeyUsage     []asn1.ObjectIdentifier
		BasicConstraintsValid  bool
		IsCA                   bool
		MaxPathLen             int
		MaxPathLenZero         bool
		DNSNames, Emails, URIs []string
		IPs                    int
		SignatureAlgorithm     x509.SignatureAlgorithm
		PublicKeyAlgorithm     x509.PublicKeyAlgorithm
		Validity               time.Duration
		Extensions             []string
	}
	of := func(c *x509.Certificate) shape {
		s := shape{
			Subject: c.Subject.String(), Issuer: c.Issuer.String(),
			KeyUsage: c.KeyUsage, ExtKeyUsage: c.ExtKeyUsage, UnknownExtKeyUsage: c.UnknownExtKeyUsage,
			BasicConstraintsValid: c.BasicConstraintsValid, IsCA: c.IsCA, MaxPathLen: c.MaxPathLen, MaxPathLenZero: c.MaxPathLenZero,
			DNSNames: c.DNSNames, Emails: c.EmailAddresses, IPs: len(c.IPAddresses),
			SignatureAlgorithm: c.SignatureAlgorithm, PublicKeyAlgorithm: c.PublicKeyAlgorithm,
			Validity: c.NotAfter.Sub(c.NotBefore),
		}
		for _, u := range c.URIs {
			s.URIs = append(s.URIs, u.String())
		}
		for _, e := range c.Extensions {
			s.Extensions = append(s.Extensions, fmt.Sprintf("%v critical=%v", e.Id, e.Critical))
		}
		return s
	}
	if g, w := of(got), of(want); !reflect.DeepEqual(g, w) {
		t.Errorf("%s differs from what the live issuer emits:\n got %+v\nwant %+v", what, g, w)
	}
}

func checkP256Fixture(t *testing.T, b []byte) {
	var v vectorPKI
	decodeVector(t, b, &v)
	if v.Schema != vectorSchema || v.Instance != vectorInstance || v.ServerName != vectorServerName || v.Client == nil {
		t.Fatalf("p256.json header: %+v", v)
	}
	if v.IssuedAt != "2026-11-13T00:00:00Z" || v.VerifyAt != "2026-11-14T00:00:00Z" {
		t.Errorf("times %s, %s", v.IssuedAt, v.VerifyAt)
	}
	ca, server, client := mustCert(t, v.CA.CertPEM), mustCert(t, v.Server.CertPEM), mustCert(t, v.Client.CertPEM)
	for what, c := range map[string]*x509.Certificate{"CA": ca, "server": server, "client": client} {
		requireP256SHA256(t, what, c)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := server.Verify(x509.VerifyOptions{Roots: pool, DNSName: v.ServerName, CurrentTime: vectorVerifyAt, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("the server leaf does not verify for %s at verify_at: %v", v.ServerName, err)
	}
	if _, err := client.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: vectorVerifyAt, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("the client leaf does not verify as a client at verify_at: %v", err)
	}
	if len(client.URIs) != 1 || client.URIs[0].String() != v.Client.Identity || v.Client.Identity != vectorOperatorURI {
		t.Errorf("client URIs %v, identity %q", client.URIs, v.Client.Identity)
	}
	if ca.SerialNumber.Int64() != 1 || server.SerialNumber.Int64() != 2 || client.SerialNumber.Int64() != 3 {
		t.Errorf("serials %v %v %v, want 1 2 3", ca.SerialNumber, server.SerialNumber, client.SerialNumber)
	}
	// Each key pairs with its certificate, and each key_sha256 is its key's.
	for _, p := range []vectorPart{v.Server, *v.Client} {
		pair, err := tls.X509KeyPair([]byte(p.CertPEM), []byte(p.KeyPEM))
		if err != nil {
			t.Fatalf("%s: the key does not pair with the certificate: %v", p.Identity, err)
		}
		if fp, _ := KeyFingerprint(pair.Leaf.PublicKey); fp != p.KeySHA256 {
			t.Errorf("%s: key_sha256 %s, want %s", p.Identity, p.KeySHA256, fp)
		}
	}
	if fp, _ := KeyFingerprint(ca.PublicKey); fp != v.CA.KeySHA256 {
		t.Errorf("CA key_sha256 %s, want %s", v.CA.KeySHA256, fp)
	}

	// The fixture is what the live issuers emit, but for serial, times and keys.
	live, err := NewCA(vectorInstance)
	if err != nil {
		t.Fatal(err)
	}
	liveServer, err := live.IssueServer(vectorServerName)
	if err != nil {
		t.Fatal(err)
	}
	liveClient, err := live.IssueClient(vectorOperatorURI)
	if err != nil {
		t.Fatal(err)
	}
	sameShape(t, "the fixture CA", ca, live.Cert)
	sameShape(t, "the fixture server leaf", server, mustCert(t, string(liveServer.CertPEM)))
	sameShape(t, "the fixture client leaf", client, mustCert(t, string(liveClient.CertPEM)))
}

func checkForeignFixture(t *testing.T, b, p256 []byte) {
	var v, home vectorPKI
	decodeVector(t, b, &v)
	decodeVector(t, p256, &home)
	ca, homeCA, server := mustCert(t, v.CA.CertPEM), mustCert(t, home.CA.CertPEM), mustCert(t, v.Server.CertPEM)
	requireP256SHA256(t, "foreign CA", ca)
	requireP256SHA256(t, "foreign server", server)
	if ca.Subject.String() != homeCA.Subject.String() {
		t.Errorf("foreign CA subject %q, want the fixture's %q", ca.Subject, homeCA.Subject)
	}
	if v.CA.KeySHA256 == home.CA.KeySHA256 || ca.Equal(homeCA) {
		t.Error("the foreign CA is the fixture CA")
	}
	homePool := x509.NewCertPool()
	homePool.AddCert(homeCA)
	if _, err := server.Verify(x509.VerifyOptions{Roots: homePool, DNSName: vectorServerName, CurrentTime: vectorVerifyAt}); err == nil {
		t.Error("the foreign server leaf verifies under the fixture CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := server.Verify(x509.VerifyOptions{Roots: pool, DNSName: vectorServerName, CurrentTime: vectorVerifyAt}); err != nil {
		t.Errorf("the foreign server leaf does not verify under its own CA: %v", err)
	}
	if _, err := tls.X509KeyPair([]byte(v.Server.CertPEM), []byte(v.Server.KeyPEM)); err != nil {
		t.Errorf("foreign server pair: %v", err)
	}
}

func checkEd25519Fixture(t *testing.T, b []byte) {
	var v vectorPKI
	decodeVector(t, b, &v)
	ca, server := mustCert(t, v.CA.CertPEM), mustCert(t, v.Server.CertPEM)
	for what, c := range map[string]*x509.Certificate{"CA": ca, "server": server} {
		if _, ok := c.PublicKey.(ed25519.PublicKey); !ok || c.SignatureAlgorithm != x509.PureEd25519 {
			t.Errorf("%s is %s signed %v, want Ed25519", what, keyName(c.PublicKey), c.SignatureAlgorithm)
		}
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := server.Verify(x509.VerifyOptions{Roots: pool, DNSName: vectorServerName, CurrentTime: vectorVerifyAt, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("the Ed25519 server leaf does not verify under its CA: %v", err)
	}
	// A Go program can still serve it, though crypto.go refuses to load it.
	if _, err := tls.X509KeyPair([]byte(v.Server.CertPEM), []byte(v.Server.KeyPEM)); err != nil {
		t.Errorf("the Ed25519 server pair does not load: %v", err)
	}
	if v.CA.KeySHA256 != "" || v.Server.KeySHA256 != "" || v.Client != nil {
		t.Error("ed25519.json carries a field its shape does not have")
	}
}

// checkRequestShapes holds requests.json to its pinned layout: the six valid
// requests in order, each the minimal template and each the shape it is
// named for, both signature halves represented, and every invalid name.
func checkRequestShapes(t *testing.T, b []byte) {
	var v vectorRequests
	decodeVector(t, b, &v)
	var names []string
	sawHigh, sawLow := false, false
	for _, r := range v.Valid {
		names = append(names, r.Name)
		der, err := pemDER(r.RequestPEM, "CERTIFICATE REQUEST")
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		tbs, _ := hex.DecodeString(r.TBSHex)
		point, _ := hex.DecodeString(r.PointHex)
		sig, _ := hex.DecodeString(r.SignatureHex)
		if !bytes.Equal(tbs, csr.RawTBSCertificateRequest) || !bytes.HasPrefix(tbs, templateTBSPrefix) || !bytes.HasSuffix(tbs, []byte{0xa0, 0x00}) {
			t.Errorf("%s: its body is not the minimal template", r.Name)
		}
		if !bytes.Equal(templateRequest(point, sig), der) {
			t.Errorf("%s: rebuilding the template from its point and signature does not give its DER", r.Name)
		}
		if !bytes.Equal(sig, csr.Signature) || len(point) != 65 || point[0] != 0x04 {
			t.Errorf("%s: signature or point fields do not match the request", r.Name)
		}
		rb, sb, high, err := signatureShape(sig)
		if err != nil || rb != r.RBytes || sb != r.SBytes || high != r.HighS {
			t.Errorf("%s: r %d s %d high %v recorded, %d %d %v found (%v)", r.Name, r.RBytes, r.SBytes, r.HighS, rb, sb, high, err)
		}
		ok := map[string]bool{
			"plain": rb == 32 && sb == 32 && !high, "r_padded": rb == 33 && sb == 32, "s_padded": rb == 32 && sb == 33,
			"both_padded": rb == 33 && sb == 33, "r_short": rb <= 31, "s_short": sb <= 31,
		}[r.Name]
		if !ok {
			t.Errorf("%s: r %d bytes, s %d bytes is not the shape it is named for", r.Name, rb, sb)
		}
		sawHigh, sawLow = sawHigh || high, sawLow || !high
	}
	if !slices.Equal(names, validRequestNames) {
		t.Errorf("valid = %v, want exactly %v", names, validRequestNames)
	}
	if !sawHigh || !sawLow {
		t.Errorf("the valid vectors hold high-s %v and low-s %v; want both", sawHigh, sawLow)
	}
	if v.KeyOnly.Name != "extensions_ignored" {
		t.Errorf("key_only is %q", v.KeyOnly.Name)
	}
	var invalid []string
	for _, r := range v.Invalid {
		invalid = append(invalid, r.Name+":"+r.Refusal)
	}
	want := []string{
		"ed25519_key:key-algorithm", "rsa_key:key-algorithm", "mldsa44_key:key-algorithm", "p384_key:curve",
		"ecdsa_sha1:signature-algorithm", "ecdsa_sha384:signature-algorithm", "bad_signature:signature",
		"compressed_point:malformed", "trailing_data:malformed", "not_a_request:malformed",
	}
	if !slices.Equal(invalid, want) {
		t.Errorf("invalid = %v, want %v", invalid, want)
	}
}

func checkTokenVector(t *testing.T, b, p256 []byte) {
	var v vectorToken
	var home vectorPKI
	decodeVector(t, b, &v)
	decodeVector(t, p256, &home)
	if v.Label != vectorTokenLabel {
		t.Errorf("label %q", v.Label)
	}
	if v.LeafPEM != home.Client.CertPEM {
		t.Error("leaf_pem is not the fixture's client leaf")
	}
	leaf, twin, ca := mustCert(t, v.LeafPEM), mustCert(t, v.TwinPEM), mustCert(t, home.CA.CertPEM)
	if bytes.Equal(leaf.Raw, twin.Raw) {
		t.Fatal("the twin is the leaf; it proves nothing")
	}
	if !bytes.Equal(leaf.RawTBSCertificate, twin.RawTBSCertificate) {
		t.Error("the twin's signed body differs from the leaf's")
	}
	for what, c := range map[string]*x509.Certificate{"leaf": leaf, "twin": twin} {
		if err := c.CheckSignatureFrom(ca); err != nil {
			t.Errorf("the %s does not verify under the fixture CA: %v", what, err)
		}
		if got := vectorTokenOf(v.Label, c); got != v.Token {
			t.Errorf("the %s's token is %s, the file says %s", what, got, v.Token)
		}
	}
	if len(v.Token) != 16 {
		t.Errorf("token %q is not 16 hex characters", v.Token)
	}
}

// A-T4. Every valid request and key_only is accepted with the key its
// key_sha256 names; every invalid one is refused with exactly its refusal.
func TestCheckRequestVectors(t *testing.T) {
	var v vectorRequests
	readVector(t, "requests.json", &v)
	accept := append(slices.Clone(v.Valid), vectorValidRequest{Name: v.KeyOnly.Name, RequestPEM: v.KeyOnly.RequestPEM, KeySHA256: v.KeyOnly.KeySHA256})
	for _, r := range accept {
		der, err := pemDER(r.RequestPEM, "CERTIFICATE REQUEST")
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		pub, err := CheckRequest(der)
		if err != nil {
			t.Errorf("%s refused: %v", r.Name, err)
			continue
		}
		if fp, _ := KeyFingerprint(pub); fp != r.KeySHA256 {
			t.Errorf("%s: key %s, want %s", r.Name, fp, r.KeySHA256)
		}
	}
	if len(v.Invalid) == 0 {
		t.Fatal("no invalid vectors")
	}
	for _, r := range v.Invalid {
		der, err := pemDER(r.RequestPEM, "CERTIFICATE REQUEST")
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		pub, err := CheckRequest(der)
		var re *RequestError
		switch {
		case err == nil:
			t.Errorf("%s accepted (key %v); want refused as %s", r.Name, keyName(pub), r.Refusal)
		case !errors.As(err, &re):
			t.Errorf("%s: %v is not a *RequestError", r.Name, err)
		case re.Refusal != r.Refusal:
			t.Errorf("%s refused as %s (%s), want %s", r.Name, re.Refusal, re.Detail, r.Refusal)
		case pub != nil:
			t.Errorf("%s: refused but a key was returned", r.Name)
		}
	}
}

// A-T9. The fingerprint is SHA-256 over the SubjectPublicKeyInfo DER — not the
// raw point — and agrees with every key_sha256 in the vectors.
func TestKeyFingerprintIsSHA256OfTheSPKI(t *testing.T) {
	key := vectorP256("fingerprint")
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(spki)
	got, err := KeyFingerprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("KeyFingerprint = %s, want SHA-256 of the SPKI %x", got, want)
	}
	point, _ := key.PublicKey.Bytes()
	if raw := sha256.Sum256(point); got == hex.EncodeToString(raw[:]) {
		t.Error("KeyFingerprint hashes the raw point, not the SubjectPublicKeyInfo")
	}
	if _, err := KeyFingerprint("not a key"); err == nil {
		t.Error("KeyFingerprint accepted something that is not a key")
	}

	var p256 vectorPKI
	readVector(t, "p256.json", &p256)
	for _, p := range []vectorPart{p256.CA, p256.Server, *p256.Client} {
		if fp, _ := KeyFingerprint(mustCert(t, p.CertPEM).PublicKey); fp != p.KeySHA256 {
			t.Errorf("p256.json: %s key_sha256 %s, KeyFingerprint %s", p.Identity, p.KeySHA256, fp)
		}
	}
	var reqs vectorRequests
	readVector(t, "requests.json", &reqs)
	for _, r := range reqs.Valid {
		point, _ := hex.DecodeString(r.PointHex)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		if fp, _ := KeyFingerprint(pub); fp != r.KeySHA256 {
			t.Errorf("requests.json %s: key_sha256 %s, KeyFingerprint of its point %s", r.Name, r.KeySHA256, fp)
		}
	}
}
