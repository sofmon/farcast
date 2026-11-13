package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ADR 0020's Apple regression (ADR 0021 Verification 1), its Go half: three
// TLS servers on 127.0.0.1 that FarSightKit's FarSightTLSTests reach with
// URLSession and NWConnection. Every one runs FatLine's own ServerTLSConfig,
// admitting only the P-256 fixture's operator leaf, and they differ only in
// the certificate they present:
//
//	p256     the fixture's server leaf (testdata/pki/p256.json)
//	foreign  a leaf from another P-256 CA with the same subject (foreign.json)
//	ed25519  a leaf of the PKI ADR 0020 retired (ed25519.json)
//
// The keys are the vectors' own, which FarSightKit copies byte for byte
// (check.sh 7a), so both sides hold the same PKI. ./check.sh compiles this
// package's tests and runs TestServeAppleFixture from the package directory,
// because the vectors are read relative to it; farsight/client/apple/README.md
// says how to run it by hand. Nothing here logs key material.

// appleFixtureEnv names the file TestServeAppleFixture writes its addresses to.
const appleFixtureEnv = "FARCAST_APPLE_FIXTURE"

// appleFixturePart is one certificate of a vector file, with its key.
type appleFixturePart struct {
	Identity string `json:"identity"`
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`
}

// appleFixtureFile is the part of p256.json, foreign.json and ed25519.json
// the servers use (design 1.3).
type appleFixtureFile struct {
	Schema     int               `json:"schema"`
	ServerName string            `json:"server_name"`
	VerifyAt   time.Time         `json:"verify_at"`
	CA         appleFixturePart  `json:"ca"`
	Server     appleFixturePart  `json:"server"`
	Client     *appleFixturePart `json:"client"`
}

// appleFixtureAddrs is the address file: where each server listens.
type appleFixtureAddrs struct {
	P256    string `json:"p256"`
	Foreign string `json:"foreign"`
	Ed25519 string `json:"ed25519"`
}

// appleFixtureEcho is every server's answer: the client as the server saw it.
type appleFixtureEcho struct {
	Client string `json:"client"` // the first URI of the client's leaf
	Key    string `json:"key"`    // "ECDSA P-256" or "other"
	TLS    string `json:"tls"`    // "1.3" or "other"
	Proto  string `json:"proto"`  // r.Proto: HTTP/2.0 or HTTP/1.1
}

// appleFixtureServers are the three running servers.
type appleFixtureServers struct {
	addrs   appleFixtureAddrs
	fixture appleFixtureFile // p256.json
	servers []*http.Server
	wg      sync.WaitGroup
	failed  chan error // a server that stopped serving before close
}

func appleFixtureLoad(name string) (appleFixtureFile, error) {
	var f appleFixtureFile
	data, err := os.ReadFile(filepath.Join("testdata", "pki", name))
	if err != nil {
		return f, fmt.Errorf("the Apple fixture reads the PKI vectors relative to fatline/internal/crypto: %w", err)
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return f, fmt.Errorf("%s: %w", name, err)
	}
	if f.Schema != 1 || f.ServerName == "" || f.VerifyAt.IsZero() || f.CA.CertPEM == "" || f.Server.CertPEM == "" || f.Server.KeyPEM == "" {
		return f, fmt.Errorf("%s: not a schema 1 PKI vector with a CA and a server leaf", name)
	}
	return f, nil
}

// appleFixtureEchoHandler answers with who the client was. The key check is
// written out here rather than calling IsP256, so the echo stays a witness
// independent of what it reports on.
func appleFixtureEchoHandler(w http.ResponseWriter, r *http.Request) {
	echo := appleFixtureEcho{Key: "other", TLS: "other", Proto: r.Proto}
	if r.TLS != nil {
		if r.TLS.Version == tls.VersionTLS13 {
			echo.TLS = "1.3"
		}
		if len(r.TLS.PeerCertificates) > 0 {
			leaf := r.TLS.PeerCertificates[0]
			if len(leaf.URIs) > 0 {
				echo.Client = leaf.URIs[0].String()
			}
			if k, ok := leaf.PublicKey.(*ecdsa.PublicKey); ok && k.Curve == elliptic.P256() {
				echo.Key = "ECDSA P-256"
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(echo)
}

// appleFixtureStart starts the three servers on 127.0.0.1, each logging its
// refusals (a TLS handshake error, never key material) to errorLog.
func appleFixtureStart(errorLog io.Writer) (*appleFixtureServers, error) {
	p256, err := appleFixtureLoad("p256.json")
	if err != nil {
		return nil, err
	}
	foreign, err := appleFixtureLoad("foreign.json")
	if err != nil {
		return nil, err
	}
	ed, err := appleFixtureLoad("ed25519.json")
	if err != nil {
		return nil, err
	}
	if p256.Client == nil || p256.Client.Identity == "" {
		return nil, errors.New("p256.json: no client leaf")
	}
	clientCA, err := PoolFromPEM([]byte(p256.CA.CertPEM))
	if err != nil {
		return nil, err
	}
	operator, verifyAt := p256.Client.Identity, p256.VerifyAt

	s := &appleFixtureServers{fixture: p256, failed: make(chan error, 3)}
	for _, server := range []struct {
		name string
		leaf appleFixturePart
		addr *string
	}{
		{"p256", p256.Server, &s.addrs.P256},
		{"foreign", foreign.Server, &s.addrs.Foreign},
		{"ed25519", ed.Server, &s.addrs.Ed25519},
	} {
		// tls.X509KeyPair reads an Ed25519 PKCS#8 key too: a Go program can
		// still serve the retired PKI, although crypto.go refuses to issue
		// or load it.
		cert, err := tls.X509KeyPair([]byte(server.leaf.CertPEM), []byte(server.leaf.KeyPEM))
		if err != nil {
			return nil, errors.Join(fmt.Errorf("%s: %w", server.name, err), s.close())
		}
		cfg := ServerTLSConfig(cert, clientCA, func(uri string) bool { return uri == operator })
		// The vectors' clock: the fixture's leaves stay valid however old
		// the files grow.
		cfg.Time = func() time.Time { return verifyAt }
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, errors.Join(fmt.Errorf("%s: %w", server.name, err), s.close())
		}
		*server.addr = l.Addr().String()
		srv := &http.Server{
			Handler:           http.HandlerFunc(appleFixtureEchoHandler),
			TLSConfig:         cfg,
			ReadHeaderTimeout: 10 * time.Second,
			ErrorLog:          log.New(errorLog, server.name+": ", 0),
		}
		s.servers = append(s.servers, srv)
		s.wg.Add(1)
		go func(name string) {
			defer s.wg.Done()
			// ServeTLS offers h2 and http/1.1 over ALPN, as FatLine serves.
			if err := srv.ServeTLS(l, "", ""); !errors.Is(err, http.ErrServerClosed) {
				s.failed <- fmt.Errorf("the %s server stopped: %w", name, err)
			}
		}(server.name)
	}
	return s, nil
}

// close stops every server and reports any that had stopped on its own.
func (s *appleFixtureServers) close() error {
	var errs []error
	for _, srv := range s.servers {
		if err := srv.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	s.wg.Wait()
	close(s.failed)
	for err := range s.failed {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func appleFixtureWriteAddrs(path string, addrs appleFixtureAddrs) error {
	data, err := json.Marshal(addrs)
	if err != nil {
		return err
	}
	// Renamed into place, so a reader polling for the file never sees half of it.
	if err := os.WriteFile(path+".tmp", data, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// TestServeAppleFixture serves ADR 0020's Apple regression until its stdin
// closes: ./check.sh holds the other end of a FIFO open while FarSightKit's
// tests run, and closes it to stop the servers. Run any other way, it skips.
// It must be run as a compiled test binary, because go test hands a test
// binary an empty stdin, and from this package's directory.
func TestServeAppleFixture(t *testing.T) {
	out := os.Getenv(appleFixtureEnv)
	if out == "" {
		t.Skip("serves only for ./check.sh's Apple regression: " + appleFixtureEnv + " names the address file it writes")
	}
	s, err := appleFixtureStart(os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if err := appleFixtureWriteAddrs(out, s.addrs); err != nil {
		t.Error(err)
		if err := s.close(); err != nil {
			t.Error(err)
		}
		return
	}
	log.Printf("ADR 0020 Apple fixture: p256 %s, foreign %s, ed25519 %s; serving until stdin closes", s.addrs.P256, s.addrs.Foreign, s.addrs.Ed25519)

	stdin := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, os.Stdin)
		stdin <- err
	}()
	select {
	case err := <-stdin:
		if err != nil {
			t.Errorf("reading stdin: %v", err)
		}
	case err := <-s.failed:
		t.Error(err)
	}
	if err := s.close(); err != nil {
		t.Error(err)
	}
	log.Printf("ADR 0020 Apple fixture: stopped")
}

// appleFixtureLog collects the servers' refusals; three loggers write to it.
type appleFixtureLog struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *appleFixtureLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *appleFixtureLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// appleFixtureGet fetches https://<addr>/ with a Go client: the operator
// leaf presented when withClient, trusting only rootPEM, at the vectors' clock.
func appleFixtureGet(t *testing.T, f appleFixtureFile, addr, rootPEM string, withClient bool) (appleFixtureEcho, *tls.ConnectionState, error) {
	t.Helper()
	roots, err := PoolFromPEM([]byte(rootPEM))
	if err != nil {
		t.Fatal(err)
	}
	var cert tls.Certificate
	if withClient {
		if cert, err = tls.X509KeyPair([]byte(f.Client.CertPEM), []byte(f.Client.KeyPEM)); err != nil {
			t.Fatal(err)
		}
	}
	cfg := ClientTLSConfig(cert, roots, f.ServerName)
	if !withClient {
		cfg.Certificates = nil
	}
	cfg.Time = func() time.Time { return f.VerifyAt }
	transport := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		return appleFixtureEcho{}, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var echo appleFixtureEcho
	if resp.StatusCode != http.StatusOK {
		return echo, resp.TLS, fmt.Errorf("status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		return echo, resp.TLS, err
	}
	return echo, resp.TLS, nil
}

// TestAppleFixtureServers holds the Go half of the regression to what the
// Swift half expects of it, with Go's own TLS client, so a broken fixture
// fails here rather than as a puzzling Apple failure: the P-256 server admits
// the operator leaf and echoes it; a client trusting the fixture CA refuses
// the foreign server; the Ed25519 server does present the retired PKI and is
// reachable by a client that speaks it; and FatLine's config refuses a client
// with no certificate.
func TestAppleFixtureServers(t *testing.T) {
	errorLog := &appleFixtureLog{}
	s, err := appleFixtureStart(errorLog)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.close(); err != nil {
			t.Error(err)
		}
	}()
	f := s.fixture
	for _, addr := range []string{s.addrs.P256, s.addrs.Foreign, s.addrs.Ed25519} {
		if host, _, err := net.SplitHostPort(addr); err != nil || host != "127.0.0.1" {
			t.Errorf("a fixture server listens at %q, not on 127.0.0.1", addr)
		}
	}

	echo, cs, err := appleFixtureGet(t, f, s.addrs.P256, f.CA.CertPEM, true)
	if err != nil {
		t.Fatalf("the P-256 server refused the operator leaf: %v", err)
	}
	want := appleFixtureEcho{Client: f.Client.Identity, Key: "ECDSA P-256", TLS: "1.3", Proto: "HTTP/2.0"}
	if echo != want {
		t.Errorf("the P-256 server echoed %+v, want %+v", echo, want)
	}
	if !IsP256(cs.PeerCertificates[0].PublicKey) {
		t.Error("the P-256 server presented a key that is not P-256")
	}

	if _, _, err := appleFixtureGet(t, f, s.addrs.Foreign, f.CA.CertPEM, true); err == nil {
		t.Error("a client trusting the fixture CA reached the foreign server")
	} else if !errors.As(err, new(x509.UnknownAuthorityError)) {
		t.Errorf("the foreign server was refused for another reason: %v", err)
	}

	ed, err := appleFixtureLoad("ed25519.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := appleFixtureGet(t, f, s.addrs.Ed25519, f.CA.CertPEM, true); err == nil {
		t.Error("a client trusting the fixture CA reached the Ed25519 server")
	}
	echo, cs, err = appleFixtureGet(t, f, s.addrs.Ed25519, ed.CA.CertPEM, true)
	if err != nil {
		t.Fatalf("a Go client that trusts the Ed25519 CA could not reach the Ed25519 server, so the Apple negative would prove nothing: %v", err)
	}
	if got := cs.PeerCertificates[0].PublicKeyAlgorithm; got != x509.Ed25519 {
		t.Errorf("the Ed25519 server presented a %v key", got)
	}
	if echo.Key != "ECDSA P-256" || echo.Client != f.Client.Identity {
		t.Errorf("the Ed25519 server echoed %+v", echo)
	}

	if _, _, err := appleFixtureGet(t, f, s.addrs.P256, f.CA.CertPEM, false); err == nil {
		t.Error("FatLine's server config admitted a client with no certificate")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(errorLog.String(), "p256: http: TLS handshake error") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(errorLog.String(), "p256: http: TLS handshake error") {
		t.Errorf("the P-256 server logged no handshake refusal:\n%s", errorLog.String())
	}
}
