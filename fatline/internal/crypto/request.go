package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
)

// The refusal codes of an enrolment request, one per check of ADR 0020
// decision 3. They are stable strings: the CLI prints them and the
// conformance vectors (testdata/pki/requests.json) pin each invalid request
// to exactly one.
const (
	RefusalMalformed          = "malformed"
	RefusalKeyAlgorithm       = "key-algorithm"
	RefusalCurve              = "curve"
	RefusalSignatureAlgorithm = "signature-algorithm"
	RefusalSignature          = "signature"
)

// RequestError is an enrolment request refused by CheckRequest.
type RequestError struct {
	Refusal string // one of the Refusal* codes
	Detail  string // what was found, never the request's bytes
}

func (e *RequestError) Error() string {
	return "fatline: enrolment request refused (" + e.Refusal + "): " + e.Detail
}

// CheckRequest applies ADR 0020 decision 3's checks to a PKCS#10 request and
// returns the request's key. In order:
//
//  1. it parses (trailing data and a compressed point fail here);
//  2. its key algorithm is ECDSA;
//  3. its curve is P-256;
//  4. its signature algorithm is ECDSA with SHA-256;
//  5. its self-signature verifies, which proves the sender holds the key.
//
// The explicit checks run before the signature check because
// CertificateRequest.CheckSignature alone accepts ECDSA-SHA1 and verifies
// Ed25519, RSA, other curves and ML-DSA. Nothing else in the request is read:
// a subject, SANs, extensions or a validity it asks for are never honoured.
func CheckRequest(requestDER []byte) (*ecdsa.PublicKey, error) {
	csr, err := x509.ParseCertificateRequest(requestDER)
	if err != nil {
		return nil, &RequestError{Refusal: RefusalMalformed, Detail: "it does not parse as a PKCS#10 certificate request (" + err.Error() + ")"}
	}
	if csr.PublicKeyAlgorithm != x509.ECDSA {
		return nil, &RequestError{Refusal: RefusalKeyAlgorithm, Detail: "its key is " + csr.PublicKeyAlgorithm.String() + ", not ECDSA"}
	}
	if !IsP256(csr.PublicKey) {
		return nil, &RequestError{Refusal: RefusalCurve, Detail: "its key is " + keyName(csr.PublicKey) + ", not ECDSA P-256"}
	}
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return nil, &RequestError{Refusal: RefusalSignatureAlgorithm, Detail: "it is signed " + csr.SignatureAlgorithm.String() + ", not ECDSA-SHA256"}
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, &RequestError{Refusal: RefusalSignature, Detail: "its self-signature does not verify, so it does not prove the sender holds the key"}
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		// IsP256 has already proved the type; this keeps the assertion checked.
		return nil, &RequestError{Refusal: RefusalKeyAlgorithm, Detail: "its key is not ECDSA"}
	}
	return pub, nil
}
