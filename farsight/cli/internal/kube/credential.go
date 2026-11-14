package kube

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
)

// Credential is one service account's signing key.
type Credential struct {
	Email          string
	PrivateKeyID   string // "" when unknown; sent as the JWT kid
	PrivateKeyPEM  []byte // RSA, PKCS#1 or PKCS#8
	TokenURI       string // as the key file recorded it, "" when absent; paired (§3.2), never dialled
	UniverseDomain string // as the key file recorded it, "" when absent; paired (§3.2)
}

// msgCredential is ParseServiceAccountJSON's one refusal. Its %s names the
// field that failed and never the field's value.
const msgCredential = "the stored service-account key is not a service-account key farcast uses (%s)"

// serviceAccountFile is the part of a Google service-account key file farcast
// reads. Every other field (project_id, client_id, the certificate URLs) is
// ignored: Google's files carry more than this, and their presence decides
// nothing.
type serviceAccountFile struct {
	Type           string `json:"type"`
	ClientEmail    string `json:"client_email"`
	PrivateKey     string `json:"private_key"`
	PrivateKeyID   string `json:"private_key_id"`
	TokenURI       string `json:"token_uri"`
	UniverseDomain string `json:"universe_domain"`
}

// ParseServiceAccountJSON reads a service-account key file's JSON (credentials.yaml's
// service_account_key) without deciding where it may be used (§3.2). It refuses,
// with ErrCredentialInvalid, anything that is not a service-account key with an
// email and an RSA private key. Where the key may go is kube.New's pairing rule.
//
// So a Google key and a loopback test key both parse: an email's domain, a
// token_uri on 127.0.0.1 and a universe_domain are kept as recorded, for the
// pairing to judge.
func ParseServiceAccountJSON(b []byte) (Credential, error) {
	var f serviceAccountFile
	if err := json.Unmarshal(b, &f); err != nil {
		// A type error names the field it met, never the value; any other
		// failure is the body as a whole.
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) && te.Field != "" {
			return Credential{}, refuse(ErrCredentialInvalid, msgCredential, te.Field)
		}
		return Credential{}, refuse(ErrCredentialInvalid, msgCredential, "not a JSON object")
	}
	if f.Type != "service_account" {
		return Credential{}, refuse(ErrCredentialInvalid, msgCredential, "type")
	}
	if local, domain, ok := strings.Cut(f.ClientEmail, "@"); !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return Credential{}, refuse(ErrCredentialInvalid, msgCredential, "client_email")
	}
	if !isRSAPrivateKeyPEM([]byte(f.PrivateKey)) {
		return Credential{}, refuse(ErrCredentialInvalid, msgCredential, "private_key")
	}
	if f.TokenURI != "" {
		u, err := url.Parse(f.TokenURI)
		if err != nil || !u.IsAbs() || u.Scheme != "https" || u.Host == "" {
			return Credential{}, refuse(ErrCredentialInvalid, msgCredential, "token_uri")
		}
	}
	return Credential{
		Email:          f.ClientEmail,
		PrivateKeyID:   f.PrivateKeyID,
		PrivateKeyPEM:  []byte(f.PrivateKey),
		TokenURI:       f.TokenURI,
		UniverseDomain: f.UniverseDomain,
	}, nil
}

// isRSAPrivateKeyPEM reports whether pemBytes holds a PEM block whose
// contents parse as an RSA private key, in PKCS#8 or PKCS#1, the two forms
// the vendored 2LO signer reads (cloud.google.com/go/auth internal.ParseKey).
// The 2LO header is always RS256, so any other key type is refused here
// rather than at the first mint.
func isRSAPrivateKeyPEM(pemBytes []byte) bool {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return false
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		_, ok := k.(*rsa.PrivateKey)
		return ok
	}
	_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return err == nil
}
