package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// The in-cluster contract: the API server's address arrives as environment,
// and the identity as files the kubelet maintains.
const (
	tokenFile     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caFile        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var (
	// ErrNotFound and friends let callers branch on what went wrong without
	// parsing prose. They are the small part of client-go's error taxonomy
	// this client actually needs.
	ErrNotFound     = errors.New("kube: object not found")
	ErrForbidden    = errors.New("kube: forbidden")
	ErrUnauthorized = errors.New("kube: unauthorized")
	ErrConflict     = errors.New("kube: conflict")
)

// APIError carries the server's own Status object alongside the sentinel, so a
// log line can say what the API server said rather than what this package
// guessed.
type APIError struct {
	Status Status
	kind   error
}

func (e *APIError) Error() string {
	msg := e.Status.Message
	if msg == "" {
		msg = e.Status.Reason
	}
	return fmt.Sprintf("kube: api error %d: %s", e.Status.Code, msg)
}

func (e *APIError) Unwrap() error { return e.kind }

// Client talks to the Kubernetes API server over HTTPS and JSON.
//
// It is deliberately small — see [ADR 0009] decision 3. The scope is: list
// pods and deployments, and patch a deployment's scale subresource. It polls;
// it does not watch. For a kernel, a loop that cannot silently stop
// reconciling is worth more than freshness measured in seconds.
//
// [ADR 0009]: ../../docs/adr/0009-technocore-kernel-and-cost-metering.md
type Client struct {
	base      *url.URL
	http      *http.Client
	tokenPath string
	namespace string
}

// InCluster builds a Client from the ServiceAccount the pod is running as.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("kube: not running in a cluster (KUBERNETES_SERVICE_HOST/PORT unset)")
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("kube: read the cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("kube: the cluster CA file contains no usable certificate")
	}
	ns, err := os.ReadFile(namespaceFile)
	if err != nil {
		return nil, fmt.Errorf("kube: read the pod's namespace: %w", err)
	}

	base, err := url.Parse("https://" + net(host, port))
	if err != nil {
		return nil, fmt.Errorf("kube: build the API server URL: %w", err)
	}
	return &Client{
		base:      base,
		tokenPath: tokenFile,
		namespace: strings.TrimSpace(string(ns)),
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			},
		},
	}, nil
}

// New builds a Client against an explicit endpoint. It exists for tests and
// for a caller that has already established trust; InCluster is the
// production path.
func New(endpoint, tokenPath, namespace string, hc *http.Client) (*Client, error) {
	base, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("kube: parse endpoint: %w", err)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: base, tokenPath: tokenPath, namespace: namespace, http: hc}, nil
}

// Namespace is the namespace this pod runs in.
func (c *Client) Namespace() string { return c.namespace }

// ListPods returns the pods in a namespace, optionally narrowed by a label
// selector such as "app.kubernetes.io/managed-by=farcast".
func (c *Client) ListPods(ctx context.Context, namespace, selector string) ([]Pod, error) {
	var out PodList
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods", url.PathEscape(namespace))
	if err := c.get(ctx, path, selector, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// ListDeployments returns the deployments in a namespace.
func (c *Client) ListDeployments(ctx context.Context, namespace, selector string) ([]Deployment, error) {
	var out DeploymentList
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments", url.PathEscape(namespace))
	if err := c.get(ctx, path, selector, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// Scale sets a deployment's replica count through the scale subresource.
//
// A merge patch against /scale, rather than a full update of the Deployment:
// an update would require reading the object, changing one field and writing
// the whole thing back, which races with every other writer and is how a
// controller silently reverts somebody else's change. A merge patch touches
// the one field it names.
func (c *Client) Scale(ctx context.Context, namespace, name string, replicas int) error {
	if replicas < 0 {
		return fmt.Errorf("kube: replicas must not be negative, got %d", replicas)
	}
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s/scale",
		url.PathEscape(namespace), url.PathEscape(name))
	body := fmt.Sprintf(`{"spec":{"replicas":%d}}`, replicas)
	return c.do(ctx, http.MethodPatch, path, "", "application/merge-patch+json", []byte(body), nil)
}

func (c *Client) get(ctx context.Context, path, selector string, out any) error {
	return c.do(ctx, http.MethodGet, path, selector, "", nil, out)
}

func (c *Client) do(ctx context.Context, method, path, selector, contentType string, body []byte, out any) error {
	u := *c.base
	u.Path = path
	if selector != "" {
		u.RawQuery = url.Values{"labelSelector": {selector}}.Encode()
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return fmt.Errorf("kube: build request: %w", err)
	}

	// The token is read per request, never cached for the process lifetime.
	// A projected ServiceAccount token is rotated by the kubelet while the
	// pod runs, so a client that reads it once works perfectly until it
	// abruptly does not — 401s an hour in, from a process that has been
	// healthy since start-up. Re-reading a small file is the cheap half of
	// that trade.
	token, err := c.token()
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kube: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("kube: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return apiError(resp.StatusCode, payload)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("kube: decode %s: %w", path, err)
	}
	return nil
}

func (c *Client) token() (string, error) {
	if c.tokenPath == "" {
		return "", nil
	}
	b, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return "", fmt.Errorf("kube: read the service account token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// apiError turns a non-2xx into a typed error. The body is a Status object
// when the API server produced it; when something in front of the API server
// produced it (a proxy, a sidecar) the body is not JSON, and the HTTP code is
// still worth reporting rather than losing to a decode failure.
func apiError(code int, payload []byte) error {
	st := Status{Code: code}
	if err := json.Unmarshal(payload, &st); err != nil || st.Code == 0 {
		st = Status{Code: code, Message: strings.TrimSpace(string(payload))}
	}
	var kind error
	switch code {
	case http.StatusNotFound:
		kind = ErrNotFound
	case http.StatusForbidden:
		kind = ErrForbidden
	case http.StatusUnauthorized:
		kind = ErrUnauthorized
	case http.StatusConflict:
		kind = ErrConflict
	}
	return &APIError{Status: st, kind: kind}
}

func net(host, port string) string {
	if strings.Contains(host, ":") { // IPv6 literal
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
