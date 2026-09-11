package keyholder

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// TLS policy for the keyholder's listeners.
//
// This is deliberately its own small implementation rather than an import of
// FatLine's. The modules mirror shapes, they do not import each other: making
// the process that holds key material depend on the network module's internals
// would couple the crown jewels to the one component that is a standing
// candidate for a rewrite in another language (ADR 0002).

// AllowPusher authorizes the identities permitted to change an instance's seal
// state: the operator, and — from phase 5.4 — that operator's own keeper
// devices, each with its own revocable leaf.
//
// The keeper form is honored from day one so that 5.4 adds a driver rather
// than a protocol. A keeper's authority is still narrower than an operator's,
// but that distinction is enforced by intent in the vault, not here: this
// answers only "may this peer speak to the control surface at all".
func AllowPusher(instance string) func(uri string) bool {
	operator := "farcast://" + instance + "/operator"
	keeper := "farcast://" + instance + "/keeper/"
	return func(uri string) bool {
		if uri == operator {
			return true
		}
		// A bare ".../keeper/" with no device is refused: every keeper is
		// named so that one can be revoked without revoking the fleet.
		return strings.HasPrefix(uri, keeper) && len(uri) > len(keeper)
	}
}

// ControlTLS is the mutually-authenticated listener that accepts seal-state
// changes. Only a leaf issued by the instance's own CA — which lives on the
// operator's machine and which the cloud cannot mint — reaches the handler.
func ControlTLS(cert tls.Certificate, clientCA *x509.CertPool, allow func(uri string) bool) *tls.Config {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA,
	}
	if allow != nil {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("keyholder: no client certificate")
			}
			for _, uri := range cs.PeerCertificates[0].URIs {
				if allow(uri.String()) {
					return nil
				}
			}
			// The refusal does not name what was presented: the peer knows
			// what it sent, and an error is a poor place to echo identities.
			return errors.New("keyholder: client identity is not authorized to change the seal state")
		}
	}
	return cfg
}

// DataTLS is the application-facing listener.
//
// It is mutually authenticated, as the control listener has been since 3.2.
// Until ADR 0018 it authenticated the server only: 3.2 shipped before any
// application had an identity, and access control was network reachability
// plus the scope a request declared — stated plainly at the time rather than
// implied, and drawn to its consequence by ADR 0017. Decision 1 of ADR 0018
// closes it: a caller presents a leaf from the instance CA, the leaf's URI
// names a role, and what it may reach follows from the role.
//
// There is no mode that requests a certificate and proceeds without one. A
// listener that admitted an unidentified caller would be exactly the fail-open
// the decision forbids, so the handshake refuses and the handler never sees
// the request.
func DataTLS(cert tls.Certificate, clientCA *x509.CertPool, allow func(uri string) bool) *tls.Config {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA,
	}
	if allow != nil {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("keyholder: no client certificate")
			}
			for _, uri := range cs.PeerCertificates[0].URIs {
				if allow(uri.String()) {
					return nil
				}
			}
			// As on the control surface: the peer knows what it sent, and an
			// error is a poor place to echo identities.
			return errors.New("keyholder: client identity is not authorized to use storage")
		}
	}
	return cfg
}

// LoadTLS builds a certificate from PEM material.
func LoadTLS(certPEM, keyPEM []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// The message never includes the material: this function is handed
		// a private key, and a malformed one must not reach a log.
		return tls.Certificate{}, errors.New("keyholder: the TLS certificate and key do not form a valid pair")
	}
	return cert, nil
}

// LoadCAPool builds a verification pool from a CA certificate.
func LoadCAPool(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("keyholder: no certificate found in the CA material")
	}
	return pool, nil
}
