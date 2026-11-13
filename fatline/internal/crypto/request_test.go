package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// keyOnlyRequest is requests.json's extensions_ignored: a valid request that
// asks for a subject, SANs, CA extensions and a validity of its own.
func keyOnlyRequest(t *testing.T) (*x509.CertificateRequest, []byte) {
	t.Helper()
	var v vectorRequests
	readVector(t, "requests.json", &v)
	der, err := pemDER(v.KeyOnly.RequestPEM, "CERTIFICATE REQUEST")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr, der
}

// A-T5. ADR 0020 decision 3: issuance by request honours the request's key
// and nothing else in it — not its subject, its SANs, its EKU, its basic
// constraints, its key usage or the validity it asks for.
func TestIssueFromRequestHonoursOnlyTheKey(t *testing.T) {
	csr, der := keyOnlyRequest(t)
	// The vector must ask for what the test says is ignored, or the test
	// proves nothing.
	askedPeriod := slices.ContainsFunc(csr.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oidPrivateKeyUsagePeriod) })
	if csr.Subject.CommonName == "" || len(csr.DNSNames) == 0 || len(csr.URIs) < 2 || !askedPeriod {
		t.Fatalf("extensions_ignored no longer asks for a subject, SANs and a validity: %+v", csr)
	}

	ca, err := NewCA("fixture")
	if err != nil {
		t.Fatal(err)
	}
	const identity = "farcast://fixture/keeper/x"
	binding := vectorBundlePref + strings.Repeat("1f", 32)
	certPEM, err := ca.IssueClientFromRequest(der, identity, x509.ExtKeyUsageClientAuth, binding)
	if err != nil {
		t.Fatalf("IssueClientFromRequest: %v", err)
	}
	cert := leafCert(t, certPEM)

	if cert.Subject.String() != "CN="+identity {
		t.Errorf("subject %q, want only CN=%s", cert.Subject, identity)
	}
	var uris []string
	for _, u := range cert.URIs {
		uris = append(uris, u.String())
	}
	if !slices.Equal(uris, []string{identity, binding}) {
		t.Errorf("URIs %v, want [%s %s]", uris, identity, binding)
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 {
		t.Errorf("SANs from the request: DNS %v IP %v email %v", cert.DNSNames, cert.IPAddresses, cert.EmailAddresses)
	}
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || len(cert.UnknownExtKeyUsage) != 0 {
		t.Errorf("EKU %v %v, want [ClientAuth]", cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
	}
	if cert.IsCA || !cert.BasicConstraintsValid {
		t.Errorf("basic constraints: valid %v, CA %v; want a leaf", cert.BasicConstraintsValid, cert.IsCA)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("key usage %v, want DigitalSignature alone", cert.KeyUsage)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got != leafValidity+time.Minute {
		t.Errorf("validity %v, want %v", got, leafValidity+time.Minute)
	}
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidPrivateKeyUsagePeriod) {
			t.Error("the leaf carries the request's privateKeyUsagePeriod")
		}
	}
	if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || !IsP256(cert.PublicKey) || !pub.Equal(cert.PublicKey) {
		t.Error("the leaf does not certify the request's key")
	}
}

// A-T6. What issuance by request refuses: a server leaf, an empty identity, a
// binding that is not an opaque URI, and every invalid request — with its
// refusal code, and no certificate.
func TestIssueFromRequestRefuses(t *testing.T) {
	ca, err := NewCA("fixture")
	if err != nil {
		t.Fatal(err)
	}
	_, req := newRequest(t)
	const identity = "farcast://fixture/keeper/x"

	if pem, err := ca.IssueClientFromRequest(req, identity, x509.ExtKeyUsageServerAuth); err == nil || pem != nil {
		t.Errorf("a server leaf was issued by request (err %v)", err)
	} else if !strings.Contains(err.Error(), "server leaves stay operator-minted") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if pem, err := ca.IssueClientFromRequest(req, "", x509.ExtKeyUsageClientAuth); err == nil || pem != nil {
		t.Errorf("a leaf with no identity was issued (err %v)", err)
	}
	for _, bad := range []string{"", "https://example.com/x", "not a uri", "/relative", "urn:"} {
		if pem, err := ca.IssueClientFromRequest(req, identity, x509.ExtKeyUsageClientAuth, bad); err == nil || pem != nil {
			t.Errorf("binding %q was accepted (err %v)", bad, err)
		}
	}
	if _, err := ca.IssueClientFromRequest(req, identity, x509.ExtKeyUsageClientAuth, vectorBundlePref+strings.Repeat("0", 64)); err != nil {
		t.Errorf("an opaque binding was refused: %v", err)
	}

	var v vectorRequests
	readVector(t, "requests.json", &v)
	for _, r := range v.Invalid {
		der, err := pemDER(r.RequestPEM, "CERTIFICATE REQUEST")
		if err != nil {
			t.Fatal(err)
		}
		pem, err := ca.IssueClientFromRequest(der, identity, x509.ExtKeyUsageClientAuth)
		var re *RequestError
		if err == nil || pem != nil {
			t.Errorf("%s: a certificate was issued", r.Name)
		} else if !errors.As(err, &re) || re.Refusal != r.Refusal {
			t.Errorf("%s: refused with %v, want refusal %s", r.Name, err, r.Refusal)
		}
	}
}
