package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// ADR 0023 decision 1: farcast turns off the two routes by which vendored
// Google code starts programs nobody asked for, process-wide, before anything
// else runs: client certificates (a certificate provider) and executable
// credential sources. ADR 0023 M2.3 (mutation 58): it also unsets the
// variables that would make a Google library log a token, or replace the
// roots a cluster endpoint is trusted on.
func TestMainTurnsClientCertificatesAndExecutablesOff(t *testing.T) {
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1")
	t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "true")
	t.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")
	t.Setenv("SSL_CERT_FILE", filepath.Join(t.TempDir(), "roots.pem"))
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	// 'version' reads the config directory: a fresh one, never the operator's.
	t.Setenv(config.EnvConfigHome, t.TempDir())

	var out, errb bytes.Buffer
	if code := Main([]string{"farcast", "version"}, bytes.NewReader(nil), &out, &errb); code != 0 {
		t.Fatalf("farcast version: exit %d, %s", code, errb.String())
	}
	for _, k := range []string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "GOOGLE_SDK_GO_LOGGING_LEVEL", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			t.Errorf("%s is still set (%q); Main must unset it", k, v)
		}
	}
	if v := os.Getenv("GOOGLE_API_USE_CLIENT_CERTIFICATE"); v != "false" {
		t.Errorf("GOOGLE_API_USE_CLIENT_CERTIFICATE = %q, want \"false\"", v)
	}
}

// The child processes of TestCertFileVariablesCannotAddARoot. TestMain runs
// certChildMain, and nothing else, when certChildEnv names a mode, so the
// child loads the system roots for the first time in certChildMain.
const (
	certChildEnv     = "FARCAST_TEST_CERT_CHILD" // certChildControl or certChildHardened
	certChildLeafEnv = "FARCAST_TEST_CERT_CHILD_LEAF"

	certChildControl  = "control"  // skips hardenEnvironment
	certChildHardened = "hardened" // calls it first, as Main does

	// The child's exit codes.
	certChildVerified   = 0
	certChildUnverified = 3
	certChildBroken     = 4

	certChildHost = "a.us-central1.gke.goog"
)

// certChildMain verifies the leaf named by certChildLeafEnv for
// certChildHost against x509.SystemCertPool, after hardenEnvironment in the
// hardened mode, and exits certChildVerified or certChildUnverified.
func certChildMain(mode string) int {
	switch mode {
	case certChildControl:
	case certChildHardened:
		if err := hardenEnvironment(); err != nil {
			fmt.Fprintln(os.Stderr, "cert child: harden:", err)
			return certChildBroken
		}
	default:
		fmt.Fprintf(os.Stderr, "cert child: unknown mode %q\n", mode)
		return certChildBroken
	}
	raw, err := os.ReadFile(os.Getenv(certChildLeafEnv))
	if err != nil {
		fmt.Fprintln(os.Stderr, "cert child: read the leaf:", err)
		return certChildBroken
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		fmt.Fprintln(os.Stderr, "cert child: the leaf is not PEM")
		return certChildBroken
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cert child: parse the leaf:", err)
		return certChildBroken
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		// No system pool at all: nothing was added to one either.
		fmt.Fprintln(os.Stderr, "cert child: no system pool:", err)
		return certChildUnverified
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: certChildHost, Roots: roots}); err != nil {
		fmt.Fprintln(os.Stderr, "cert child: not verified:", err)
		return certChildUnverified
	}
	return certChildVerified
}

// testCA writes a fresh CA's certificate and a leaf it issued for host, as
// PEM files in dir. Neither carries an issuer URL or a revocation URL, so a
// platform verifier has nothing to fetch.
func testCA(t *testing.T, dir, host string) (caPath, leafPath string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "farcast test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath, leafPath = filepath.Join(dir, "root.pem"), filepath.Join(dir, "leaf.pem")
	for path, der := range map[string][]byte{caPath: caDER, leafPath: leafDER} {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return caPath, leafPath
}

// ADR 0023 M2.3 (design §3.6, mutation 58): SSL_CERT_FILE cannot add a root
// that farcast trusts. The test binary runs twice as a child, with
// GODEBUG=x509sslcertoverrideplatform=1 and SSL_CERT_FILE naming a test CA,
// and verifies a leaf that CA issued for a.us-central1.gke.goog against the
// system pool. The control child skips hardenEnvironment and must verify,
// which shows the variable works on this platform; the hardened child calls
// it first, as Main does, and must not.
func TestCertFileVariablesCannotAddARoot(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	caPath, leafPath := testCA(t, t.TempDir(), certChildHost)

	// The child's environment: this one, without anything that would choose
	// its roots or its GODEBUG, plus the variable under test.
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "GODEBUG", "SSL_CERT_FILE", "SSL_CERT_DIR", certChildEnv, certChildLeafEnv:
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		"GODEBUG=x509sslcertoverrideplatform=1",
		"SSL_CERT_FILE="+caPath,
		certChildLeafEnv+"="+leafPath,
	)
	child := func(mode string) (int, string) {
		cmd := exec.CommandContext(t.Context(), exe, "-test.run=^$")
		cmd.Env = append(append([]string(nil), env...), certChildEnv+"="+mode)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		var exit *exec.ExitError
		switch {
		case err == nil:
			return 0, out.String()
		case errors.As(err, &exit):
			return exit.ExitCode(), out.String()
		}
		t.Fatalf("run the %s child: %v", mode, err)
		return 0, ""
	}

	switch code, out := child(certChildControl); code {
	case certChildVerified:
	case certChildUnverified:
		t.Skipf("on this platform SSL_CERT_FILE adds no root even with x509sslcertoverrideplatform=1, so the hardened child would prove nothing: %s", out)
	default:
		t.Fatalf("the control child exited %d: %s", code, out)
	}
	switch code, out := child(certChildHardened); code {
	case certChildUnverified:
	case certChildVerified:
		t.Error("after hardenEnvironment, SSL_CERT_FILE still added a root: a leaf for a.us-central1.gke.goog from the test CA verified against the system pool")
	default:
		t.Fatalf("the hardened child exited %d: %s", code, out)
	}
}
