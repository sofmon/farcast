package fatline_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/fatline"
	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
	"github.com/sofmon/farcast/fatline/tunnel"
)

// recorder sits between FatLine and the in-instance service and keeps every
// byte FatLine relayed. What FatLine writes upstream is exactly what passed
// through its address space, so this is the evidence for the claim that it
// never holds the payload in the clear.
type recorder struct {
	addr string
	mu   sync.Mutex
	seen bytes.Buffer
}

func startRecorder(t *testing.T, upstream string) *recorder {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	r := &recorder{addr: l.Addr().String()}
	go func() {
		for {
			down, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = down.Close() }()
				up, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					_, _ = io.Copy(up, io.TeeReader(down, r))
					if cw, ok := up.(interface{ CloseWrite() error }); ok {
						_ = cw.CloseWrite()
					}
				}()
				go func() {
					defer wg.Done()
					_, _ = io.Copy(down, io.TeeReader(up, r))
				}()
				wg.Wait()
			}()
		}
	}()
	return r
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen.Write(p)
}

func (r *recorder) contains(s string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Contains(r.seen.Bytes(), []byte(s))
}

// echoTLS is the stand-in for an in-instance service: it terminates its own
// TLS with its own leaf and echoes what it is told.
func startEchoTLS(t *testing.T, ca *fcrypto.CA) string {
	t.Helper()
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert(t, ca, "127.0.0.1")},
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String()
}

func startEchoPlain(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String()
}

func operatorConn(t *testing.T, ca *fcrypto.CA, addr string) *tunnel.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	id := tunnel.ClientIdentity{
		Cert:       clientCert(t, ca, "farcast://inst/operator"),
		CA:         ca.CertPool(),
		ServerName: "127.0.0.1",
	}
	conn, err := tunnel.Connect(ctx, "https://"+addr, id)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// The claim ADR 0008 decision 4 rests on: key material pushed through the
// tunnel terminates inside the keyholder, never in FatLine's address space.
//
// The negative assertion alone would pass against a design that terminated the
// payload in FatLine but happened not to log it, so the positive control below
// proves the recorder actually observes what FatLine relays.
func TestStreamPayloadNeverAppearsInFatLinesBytes(t *testing.T) {
	const marker = "MARKER-KEY-MATERIAL-c0ffee-DO-NOT-RELAY-IN-CLEAR"

	ca, _ := fcrypto.NewCA("inst")
	service := startEchoTLS(t, ca)
	rec := startRecorder(t, service)
	addr := freeAddr(t)
	startServer(t, fatline.Config{
		TunnelListen: addr,
		ServerCert:   serverCert(t, ca, "127.0.0.1"),
		ClientCA:     ca.CertPool(),
		Endpoint:     addr,
		StreamRoutes: []fatline.StreamRoute{{Name: "keyholder", Addr: rec.addr}},
	})

	conn := operatorConn(t, ca, addr)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	raw, err := conn.DialStream(ctx, "keyholder", -1)
	if err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	defer func() { _ = raw.Close() }()

	// The session that carries the payload is end-to-end with the service.
	// FatLine holds neither of its keys.
	inner := tls.Client(raw, &tls.Config{RootCAs: ca.CertPool(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
	if err := inner.HandshakeContext(ctx); err != nil {
		t.Fatalf("inner handshake: %v", err)
	}
	if _, err := inner.Write([]byte(marker)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(marker))
	if _, err := io.ReadFull(inner, buf); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf) != marker {
		t.Fatalf("echo = %q, want %q", buf, marker)
	}

	if rec.contains(marker) {
		t.Fatal("the payload appeared in the bytes FatLine relayed — it is not end-to-end encrypted")
	}
}

// The positive control for the test above. Same relay, same recorder, but the
// payload is sent WITHOUT the nested TLS session — and now the marker MUST be
// found. If this fails, the negative assertion above proves nothing, because it
// would mean the recorder never observed the traffic at all.
func TestRecorderSeesPlaintextWhenNotWrapped(t *testing.T) {
	const marker = "MARKER-CONTROL-c0ffee-SHOULD-BE-VISIBLE"

	ca, _ := fcrypto.NewCA("inst")
	service := startEchoPlain(t)
	rec := startRecorder(t, service)
	addr := freeAddr(t)
	startServer(t, fatline.Config{
		TunnelListen: addr,
		ServerCert:   serverCert(t, ca, "127.0.0.1"),
		ClientCA:     ca.CertPool(),
		Endpoint:     addr,
		StreamRoutes: []fatline.StreamRoute{{Name: "keyholder", Addr: rec.addr}},
	})

	conn := operatorConn(t, ca, addr)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	raw, err := conn.DialStream(ctx, "keyholder", -1)
	if err != nil {
		t.Fatalf("DialStream: %v", err)
	}
	defer func() { _ = raw.Close() }()

	if _, err := raw.Write([]byte(marker)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(marker))
	if _, err := io.ReadFull(raw, buf); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !rec.contains(marker) {
		t.Fatal("the recorder did not observe an unwrapped payload; the end-to-end test above would prove nothing")
	}
}

func TestStreamRouteIsClosed(t *testing.T) {
	ca, _ := fcrypto.NewCA("inst")
	service := startEchoPlain(t)
	addr := freeAddr(t)
	startServer(t, fatline.Config{
		TunnelListen: addr,
		ServerCert:   serverCert(t, ca, "127.0.0.1"),
		ClientCA:     ca.CertPool(),
		Endpoint:     addr,
		StreamRoutes: []fatline.StreamRoute{{Name: "keyholder", Addr: service}},
	})
	conn := operatorConn(t, ca, addr)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	// A name that is not in the table is refused, and an operator leaf is
	// therefore not a general-purpose port-forward into the cluster.
	for _, route := range []string{"unknown", "kubernetes.default", service} {
		if c, err := conn.DialStream(ctx, route, -1); err == nil {
			_ = c.Close()
			t.Errorf("DialStream(%q) succeeded; the route table must be closed", route)
		}
	}
}

func TestStreamOrdinals(t *testing.T) {
	ca, _ := fcrypto.NewCA("inst")
	service := startEchoPlain(t)
	host, port, _ := net.SplitHostPort(service)
	addr := freeAddr(t)
	startServer(t, fatline.Config{
		TunnelListen: addr,
		ServerCert:   serverCert(t, ca, "127.0.0.1"),
		ClientCA:     ca.CertPool(),
		Endpoint:     addr,
		StreamRoutes: []fatline.StreamRoute{
			{Name: "single", Addr: service},
			// "{ordinal}" is substituted into the host part; here every
			// index resolves to the same test listener.
			{Name: "replicas", Addr: host + ":" + port + "{ordinal}", Ordinals: 2},
		},
	})
	conn := operatorConn(t, ca, addr)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	// An ordinal outside the configured count is refused rather than dialled.
	for _, ord := range []int{2, 7, 99} {
		if c, err := conn.DialStream(ctx, "replicas", ord); err == nil {
			_ = c.Close()
			t.Errorf("ordinal %d was accepted; the range must be closed", ord)
		}
	}
	// A route without ordinals refuses one.
	if c, err := conn.DialStream(ctx, "single", 0); err == nil {
		_ = c.Close()
		t.Error("a route with no ordinals accepted one")
	}
}

func TestStreamRouteValidation(t *testing.T) {
	base := func(routes []fatline.StreamRoute) fatline.Config {
		return fatline.Config{TunnelListen: "127.0.0.1:0", StreamRoutes: routes}
	}
	bad := [][]fatline.StreamRoute{
		{{Name: "", Addr: "x:1"}},
		{{Name: "a/b", Addr: "x:1"}},
		{{Name: "a", Addr: ""}},
		{{Name: "a", Addr: "x:1"}, {Name: "a", Addr: "y:1"}},
		{{Name: "a", Addr: "x:1", Ordinals: 2}}, // ordinals but no {ordinal}
		{{Name: "a", Addr: "x-{ordinal}:1"}},    // {ordinal} but no ordinals
	}
	for _, routes := range bad {
		if _, err := fatline.New(base(routes)); err == nil {
			t.Errorf("New accepted an invalid route table: %+v", routes)
		}
	}
}
