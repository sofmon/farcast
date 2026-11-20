package planck

import (
	"context"
	"fmt"
)

// Provider manages the lifecycle of a managed Kubernetes cluster on one
// cloud. Every method honours ctx for cancellation and deadlines; cluster
// operations are minutes-long, so callers pass a ctx with a generous timeout.
type Provider interface {
	// Name is the provider's stable identifier, e.g. "gke".
	Name() string

	// Validate confirms the configured credentials are usable and carry the
	// permissions Planck needs. It creates nothing.
	Validate(ctx context.Context) error

	// CreateCluster provisions a cluster from spec and blocks until it is
	// ready to accept workloads. If a cluster with the same name and location
	// already exists, it returns that cluster rather than failing, with
	// Created false. A provider
	// that cannot hold a cluster to FarCast's isolation — the GKE adapter's
	// system-only logging (ADR 0019) — returns an error, not the cluster.
	CreateCluster(ctx context.Context, spec ClusterSpec) (*Cluster, error)

	// ClusterStatus reports the current state of the referenced cluster, or
	// ErrClusterNotFound if it does not exist.
	ClusterStatus(ctx context.Context, ref ClusterRef) (ClusterStatus, error)

	// DeleteCluster tears the cluster down and blocks until removal completes.
	// Deleting an absent cluster is not an error (idempotent cleanup).
	DeleteCluster(ctx context.Context, ref ClusterRef) error
}

// ClusterSpec is a cloud-neutral description of the cluster to create. Most
// fields are optional; the adapter fills sensible defaults.
//
// There is no node-count or machine-size field: FarCast provisions GKE
// Autopilot clusters (see docs/adr/0003-gke-autopilot.md), where the platform
// manages nodes and compute is auto-provisioned from Pod requests.
type ClusterSpec struct {
	Name     string            // DNS-label, required
	Location string            // provider-specific (GKE region); default applied if empty
	Version  string            // optional Kubernetes version; provider default if empty
	Labels   map[string]string // optional cloud resource labels
}

// ClusterRef identifies a cluster for status and delete operations.
type ClusterRef struct {
	Name     string
	Location string
}

// Cluster is a provisioned cluster and where to reach it. It carries no
// credential: the caller reaches the endpoint with its own.
type Cluster struct {
	Ref      ClusterRef
	Status   ClusterStatus
	Endpoint string // Kubernetes API server endpoint
	// SystemLogsOnly is set by a provider that has read the cluster back and
	// found it configured to send the cloud's logging service only the
	// provider's mandatory system logs — not applications' stdout and stderr.
	// That is the provider's word about its configuration, not an observation
	// of what it sends, and on Autopilot it is unwalked (ADR 0019). False
	// means not verified, not merely "off".
	SystemLogsOnly bool
	// Created is set by a provider whose CreateCluster created the cluster in
	// that call. It is false when the provider found a cluster already under
	// the name and returned it, which another machine may have created and
	// written to. Its zero value fails closed: a caller treats a cluster as
	// new only on the provider's word (farcast install warns when it is not
	// set; ADR 0023 M2.7, M2.9a).
	Created bool
}

// String renders the cluster's Ref, Status and Endpoint. It redacts
// nothing: a Cluster carries no credential.
func (c Cluster) String() string {
	return fmt.Sprintf("Cluster{Ref:%s/%s Status:%s Endpoint:%s}",
		c.Ref.Location, c.Ref.Name, c.Status, c.Endpoint)
}

// ClusterStatus is the FarCast-normalised lifecycle state of a cluster.
type ClusterStatus string

const (
	StatusProvisioning ClusterStatus = "provisioning"
	StatusRunning      ClusterStatus = "running"
	StatusDeleting     ClusterStatus = "deleting"
	StatusError        ClusterStatus = "error"
	StatusUnknown      ClusterStatus = "unknown"
)

// Config carries credentials and account scoping for a provider. Fields are
// interpreted per provider — see each adapter.
type Config struct {
	Credentials []byte            // raw credential material (e.g. GCP service-account key JSON); empty = ambient/default creds
	Project     string            // GCP project ID / AWS account context
	Location    string            // default region or zone
	Extra       map[string]string // provider-specific options
}

// String renders the config without leaking the credential material.
func (c Config) String() string {
	cred := "<none>"
	if len(c.Credentials) > 0 {
		cred = fmt.Sprintf("<redacted %d bytes>", len(c.Credentials))
	}
	return fmt.Sprintf("Config{Project:%s Location:%s Credentials:%s Extra:%v}",
		c.Project, c.Location, cred, c.Extra)
}
