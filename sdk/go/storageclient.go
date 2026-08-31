package farcast

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Environment the platform sets when it runs an application with storage.
const (
	envStorageEndpoint = "FARCAST_STORAGE_ENDPOINT"
	envStorageStatus   = "FARCAST_STORAGE_STATUS_ENDPOINT"
	envStorageScope    = "FARCAST_STORAGE_SCOPE"
	envStorageCA       = "FARCAST_STORAGE_CA"

	// envStorageServerName pins the identity the keyholder must present,
	// separately from the address used to reach it.
	//
	// The two are not the same thing and must not be conflated. A keyholder's
	// certificate carries a synthetic instance-scoped name verified against
	// the instance's own CA — never a name in public DNS — while the address
	// an application dials is whatever the platform routes it to: a cluster
	// Service, a port-forward, a future carrier. FatLine's tunnel client
	// already separates them for exactly this reason (ADR 0005's
	// carrier-independent server identity); this is the same split.
	envStorageServerName = "FARCAST_STORAGE_SERVER_NAME"
)

// Header names on the keyholder's data path. The logical key travels
// base64-encoded in a header rather than in a URL: keys are raw bytes that
// participate in authentication and are never normalized, and a URL path would
// be cleaned in transit — turning an object silently unreadable. It also keeps
// object names out of request logs.
const (
	headerKey    = "X-Farcast-Key"
	headerPrefix = "X-Farcast-Prefix"
	headerScope  = "X-Farcast-Scope"
	headerCode   = "X-Farcast-Code"
)

const storageTimeout = 30 * time.Second

// storageClient is the real StorageAPI, talking to the instance's keyholder.
type storageClient struct {
	endpoint string
	status   string
	scope    string
	http     *http.Client
}

var (
	_ StorageAPI       = (*storageClient)(nil)
	_ StorageStatusAPI = (*storageClient)(nil)
)

// storageBroken is returned when storage is configured but the configuration
// cannot be used — an unreadable CA, an unparseable endpoint.
//
// It is deliberately neither the stub nor a seal. Reporting ErrNotImplemented
// would tell an application that this build never supports storage, and
// reporting a seal would tell it to wait for an operator who has nothing to
// unseal. Both are wrong in ways that waste an outage.
type storageBroken struct{ err error }

var _ StorageAPI = storageBroken{}

func (s storageBroken) Read(context.Context, string) ([]byte, error)   { return nil, s.err }
func (s storageBroken) Write(context.Context, string, []byte) error    { return s.err }
func (s storageBroken) List(context.Context, string) ([]string, error) { return nil, s.err }
func (s storageBroken) Delete(context.Context, string) error           { return s.err }

// newStorageFromEnv builds the capability from the environment.
//
// Three outcomes, kept distinct on purpose: no endpoint means this build has
// no storage wired (the stub); a present but unusable configuration means
// something is misconfigured (storageBroken); otherwise a live client.
func newStorageFromEnv() StorageAPI {
	endpoint := strings.TrimSpace(os.Getenv(envStorageEndpoint))
	if endpoint == "" {
		return storageStub{}
	}
	client, err := newStorageClient(
		endpoint,
		strings.TrimSpace(os.Getenv(envStorageStatus)),
		strings.TrimSpace(os.Getenv(envStorageScope)),
		[]byte(os.Getenv(envStorageCA)),
		strings.TrimSpace(os.Getenv(envStorageServerName)),
	)
	if err != nil {
		return storageBroken{err: err}
	}
	return client
}

func newStorageClient(endpoint, status, scope string, caPEM []byte, serverName string) (*storageClient, error) {
	if _, err := url.Parse(endpoint); err != nil || !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("%w: %s must be an https URL", ErrStorageUnavailable, envStorageEndpoint)
	}
	if scope == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrStorageUnavailable, envStorageScope)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		// Without the instance CA there is no way to tell the keyholder from
		// anything else that answers on that address, and falling back to the
		// system roots would accept exactly that. Refuse instead.
		return nil, fmt.Errorf("%w: %s holds no certificate, so the keyholder cannot be verified", ErrStorageUnavailable, envStorageCA)
	}
	// An empty override means the endpoint's own host is the identity, which
	// is right when the two coincide and wrong the moment they do not.
	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if serverName != "" {
		tlsCfg.ServerName = serverName
	}
	return &storageClient{
		endpoint: strings.TrimRight(endpoint, "/"),
		status:   strings.TrimRight(status, "/"),
		scope:    scope,
		http: &http.Client{
			Timeout:   storageTimeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

func (c *storageClient) Read(ctx context.Context, key string) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/object", headerKey, key, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the response failed", ErrStorageUnavailable)
	}
	return data, nil
}

func (c *storageClient) Write(ctx context.Context, key string, data []byte) error {
	resp, err := c.do(ctx, http.MethodPut, "/v1/object", headerKey, key, data)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func (c *storageClient) Delete(ctx context.Context, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/v1/object", headerKey, key, nil)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func (c *storageClient) List(ctx context.Context, prefix string) ([]string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/list", headerPrefix, prefix, nil)
	if err != nil {
		// Never an empty result with a nil error: an application that read
		// "no objects" from a seal could conclude its data is gone.
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Keys []string `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("%w: the listing could not be read", ErrStorageUnavailable)
	}
	return body.Keys, nil
}

// Status reports the keyholder's condition without attempting an operation.
func (c *storageClient) Status(ctx context.Context) (StorageStatus, error) {
	st, err := c.probeStatus(ctx)
	if err != nil {
		return StorageStatus{State: StorageUnreachable}, err
	}
	return st, nil
}

// do performs one operation and maps the answer onto a sentinel.
func (c *storageClient) do(ctx context.Context, method, path, header, value string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
	}
	req.Header.Set(header, base64.StdEncoding.EncodeToString([]byte(value)))
	req.Header.Set(headerScope, c.scope)

	resp, err := c.http.Do(req)
	if err != nil {
		// The data Service is readiness-gated, so when every replica is
		// sealed it has NO endpoints and this is a dial failure rather than a
		// 503. Asking the status endpoint is what turns that into the sealed
		// contract instead of an opaque transport error — the exact case ADR
		// 0008 fixed this contract for.
		return nil, c.explainTransportFailure(ctx)
	}
	if resp.StatusCode/100 == 2 {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()
	return nil, storageError(resp.Header.Get(headerCode))
}

// explainTransportFailure decides what a failure to reach the data path means.
func (c *storageClient) explainTransportFailure(ctx context.Context) error {
	if c.status == "" {
		return fmt.Errorf("%w: the keyholder could not be reached", ErrStorageUnavailable)
	}
	st, err := c.probeStatus(ctx)
	if err != nil {
		return fmt.Errorf("%w: the keyholder could not be reached", ErrStorageUnavailable)
	}
	if st.Sealed() {
		return ErrStorageSealed
	}
	// Reachable and claiming ready, yet the data path failed: report the
	// honest answer rather than the convenient one.
	return fmt.Errorf("%w: the keyholder reports ready but its data path did not answer", ErrStorageUnavailable)
}

// probeStatus asks the status endpoint.
//
// That endpoint is plain HTTP and unauthenticated — it must be, because the
// kubelet probes it and because it has to answer while sealed. So its word is
// used for ONE thing only: deciding whether an already-failed operation should
// be reported as sealed or as unavailable. No data, no key, and no header from
// a request is ever sent to it, and a claim of "ready" from it never causes an
// operation to be retried or an error to be downgraded.
func (c *storageClient) probeStatus(ctx context.Context) (StorageStatus, error) {
	if c.status == "" {
		return StorageStatus{State: StorageUnreachable}, fmt.Errorf("%w: no status endpoint is configured", ErrStorageUnavailable)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.status+"/v1/state", nil)
	if err != nil {
		return StorageStatus{State: StorageUnreachable}, fmt.Errorf("%w: %s", ErrStorageUnavailable, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return StorageStatus{State: StorageUnreachable}, fmt.Errorf("%w: the status endpoint could not be reached", ErrStorageUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return StorageStatus{State: StorageUnreachable}, fmt.Errorf("%w: the status endpoint refused", ErrStorageUnavailable)
	}
	var body struct {
		Phase      string    `json:"phase"`
		Since      time.Time `json:"since"`
		Generation uint64    `json:"generation"`
		HoldReason string    `json:"hold_reason"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return StorageStatus{State: StorageUnreachable}, fmt.Errorf("%w: the status endpoint answered unintelligibly", ErrStorageUnavailable)
	}
	return statusFromPhase(body.Phase, body.Since, body.Generation), nil
}

// statusFromPhase maps the keyholder's phase onto the SDK's view.
//
// An unrecognized phase is reported as sealed rather than ready: a build that
// does not understand what a newer keyholder said must not conclude that
// storage is working.
func statusFromPhase(phase string, since time.Time, generation uint64) StorageStatus {
	st := StorageStatus{Since: since, Generation: generation}
	switch phase {
	case "unsealed":
		st.State = StorageReady
	case "restart-sealed":
		st.State, st.Reason = StorageSealed, SealRestart
	case "operator-hold":
		st.State, st.Reason = StorageSealed, SealOperator
	default:
		st.State, st.Reason = StorageSealed, SealRestart
	}
	return st
}
