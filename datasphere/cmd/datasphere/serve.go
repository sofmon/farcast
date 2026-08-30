package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/datasphere/keyholder"
)

// Environment carrying the transport identity. It arrives as environment
// values rather than a mounted Secret because a Secret volume is still a
// volume, and this process is specified to have none.
const (
	envTLSCA   = "DATASPHERED_TLS_CA"
	envTLSCert = "DATASPHERED_TLS_CERT"
	envTLSKey  = "DATASPHERED_TLS_KEY"
)

// shutdownGrace bounds draining once a signal arrives.
const shutdownGrace = 10 * time.Second

type serveOptions struct {
	listen       string
	statusListen string
	unsealListen string
	maxObject    int64
}

// serve runs the keyholder: the one in-cluster process that holds DataSphere
// key material, and holds it only in memory.
//
// It starts SEALED and there is no flag, file or peer that changes that. Key
// material arrives by a push from outside the cluster or it does not arrive at
// all, which is the whole of ADR 0008 expressed as a program.
func serve(ctx context.Context, opt options, sopt serveOptions, out, errw io.Writer) int {
	if opt.instance == "" || opt.bucket == "" {
		return fail(errw, "datasphere: serve requires --instance and --bucket\n")
	}

	// A traceback setting that dumps memory would print the derived bundle's
	// neighbourhood on a panic. The deployment sets GOTRACEBACK=none; refusing
	// the dangerous values here means an injected env cannot quietly undo it.
	if tb := strings.ToLower(os.Getenv("GOTRACEBACK")); tb == "crash" || tb == "all" || tb == "system" || tb == "2" {
		return fail(errw, "datasphere: refusing to serve with GOTRACEBACK=%s; it would dump this process's memory\n", tb)
	}
	if err := disableCoreDumps(); err != nil {
		return fail(errw, "datasphere: cannot disable core dumps: %v\n", err)
	}

	cert, clientCA, code := loadTransport(errw)
	if code != 0 {
		return code
	}

	provider, code := openProvider(opt, errw)
	if code != 0 {
		return code
	}

	// The bucket is verified before any listener binds: the composition root
	// is where ownership is enforced, so tampered configuration cannot point
	// this process's writes at a stranger's bucket. A failure here is a pod
	// that cannot do its job, and the platform's restart backoff is the right
	// answer — the keyholder starts sealed, so a restart loses nothing.
	ref := datasphere.BucketRef{Name: opt.bucket, Location: opt.location, Instance: opt.instance}
	if err := provider.Validate(ctx, ref); err != nil {
		return fail(errw, "datasphere: %v\n", err)
	}

	vault := keyholder.New(opt.instance)
	log := slog.New(slog.NewJSONHandler(out, nil))
	srv, err := keyholder.NewServer(keyholder.Config{
		Instance: opt.instance,
		Vault:    vault,
		Stores: func(s datasphere.Scope) (*datasphere.Store, error) {
			return datasphere.NewStore(provider, opt.bucket, s.Keyring())
		},
		MaxObjectBytes: sopt.maxObject,
		Log:            log,
	})
	if err != nil {
		return fail(errw, "datasphere: %v\n", err)
	}

	listeners := []*http.Server{
		// Status: plain HTTP, no key material, no plaintext. The kubelet
		// cannot present a client certificate, and this endpoint must answer
		// while sealed — it is what makes a seal reportable at all when the
		// data Service has no endpoints.
		{Addr: sopt.statusListen, Handler: srv.StatusHandler()},

		// Control: mutually authenticated. Only the operator's own CA can
		// mint a leaf that reaches it, and the cloud does not hold that CA.
		{
			Addr:      sopt.unsealListen,
			Handler:   srv.ControlHandler(),
			TLSConfig: keyholder.ControlTLS(cert, clientCA, keyholder.AllowPusher(opt.instance)),
		},

		// Data: server-authenticated only. See keyholder.DataTLS for why
		// there is no client certificate here in 3.2, stated rather than
		// implied.
		{
			Addr:      sopt.listen,
			Handler:   srv.DataHandler(),
			TLSConfig: keyholder.DataTLS(cert),
		},
	}

	log.Info("datasphered starting sealed",
		"instance", opt.instance,
		"data", sopt.listen, "status", sopt.statusListen, "control", sopt.unsealListen)

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, len(listeners))
	var wg sync.WaitGroup
	for _, s := range listeners {
		if s.Addr == "" {
			continue
		}
		wg.Go(func() {
			var err error
			if s.TLSConfig != nil {
				err = s.ListenAndServeTLS("", "")
			} else {
				err = s.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("datasphere: listener %s: %w", s.Addr, err)
			}
		})
	}

	var retErr error
	select {
	case <-ctx.Done():
	case retErr = <-errc:
	}

	// Forget the key material before draining, so it stops existing at the
	// first moment it is no longer needed rather than the last.
	vault.Seal(false, "")

	drain, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	for _, s := range listeners {
		if s.Addr != "" {
			_ = s.Shutdown(drain)
		}
	}
	wg.Wait()

	if retErr != nil {
		return fail(errw, "%v\n", retErr)
	}
	log.Info("datasphered stopped")
	return 0
}

// loadTransport reads the listener identity from the environment.
func loadTransport(errw io.Writer) (tls.Certificate, *x509.CertPool, int) {
	caPEM := os.Getenv(envTLSCA)
	certPEM := os.Getenv(envTLSCert)
	keyPEM := os.Getenv(envTLSKey)
	if caPEM == "" || certPEM == "" || keyPEM == "" {
		return tls.Certificate{}, nil, fail(errw,
			"datasphere: serve requires %s, %s and %s in the environment\n", envTLSCA, envTLSCert, envTLSKey)
	}
	cert, err := keyholder.LoadTLS([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return tls.Certificate{}, nil, fail(errw, "datasphere: %v\n", err)
	}
	pool, err := keyholder.LoadCAPool([]byte(caPEM))
	if err != nil {
		return tls.Certificate{}, nil, fail(errw, "datasphere: %v\n", err)
	}
	return cert, pool, 0
}

// serveFlags registers the listener flags on the shared flag set.
func serveFlags(fs *flag.FlagSet, sopt *serveOptions) {
	fs.StringVar(&sopt.listen, "listen", ":8443", "serve: application data listener")
	fs.StringVar(&sopt.statusListen, "status-listen", ":8444", "serve: probe and seal-state listener")
	fs.StringVar(&sopt.unsealListen, "unseal-listen", ":9443", "serve: mutually-authenticated control listener")
	fs.Int64Var(&sopt.maxObject, "max-object", 0, "serve: object size cap in bytes (0 uses the default)")
}
