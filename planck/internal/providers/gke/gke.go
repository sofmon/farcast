// Package gke is the GKE Autopilot adapter for Planck. It implements
// planck.Provider for the lifecycle of a GKE Autopilot cluster and
// self-registers under the name "gke".
//
// See docs/adr/0003-gke-autopilot.md for why FarCast provisions Autopilot
// clusters specifically.
package gke

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sofmon/farcast/planck"
)

const (
	providerName        = "gke"
	defaultLocation     = "us-central1"
	defaultPollInterval = 15 * time.Second
	maxNameLen          = 40 // GKE cluster name limit
)

func init() {
	planck.Register(providerName, New)
}

// New constructs the GKE provider. Config.Project (GCP project ID) is
// required; Config.Location sets the default region when a ClusterSpec omits
// one; Config.Credentials, when present, is a service-account key JSON.
//
// New does not contact GCP or resolve credentials — per the Provider contract
// that is Validate's responsibility. The underlying client is built lazily on
// first use (see client).
func New(cfg planck.Config) (planck.Provider, error) {
	if cfg.Project == "" {
		return nil, fmt.Errorf("gke: Config.Project (GCP project ID) is required")
	}
	loc := cfg.Location
	if loc == "" {
		loc = defaultLocation
	}
	return &provider{
		cfg:             cfg,
		defaultLocation: loc,
		pollInterval:    defaultPollInterval,
	}, nil
}

type provider struct {
	cfg             planck.Config
	defaultLocation string
	pollInterval    time.Duration

	mu  sync.Mutex
	api clusterAPI // built lazily on first use; see client
}

var _ planck.Provider = (*provider)(nil)

func (*provider) Name() string { return providerName }

// client lazily builds the GCP-backed clusterAPI. Construction resolves
// credentials, so — keeping with the Provider contract where Validate owns
// credential checks — it is deferred out of New and first surfaces through
// whichever operation the caller runs. Tests inject a fake api directly,
// bypassing this path.
func (p *provider) client() (clusterAPI, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.api == nil {
		api, err := newClient(p.cfg)
		if err != nil {
			return nil, err
		}
		p.api = api
	}
	return p.api, nil
}

func (p *provider) Validate(ctx context.Context) error {
	api, err := p.client()
	if err != nil {
		return err
	}
	return api.validate(ctx)
}

func (p *provider) CreateCluster(ctx context.Context, spec planck.ClusterSpec) (*planck.Cluster, error) {
	in, err := p.planCreate(spec)
	if err != nil {
		return nil, err
	}
	ref := planck.ClusterRef{Name: in.Name, Location: in.Location}

	_, exists, err := p.api.get(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("gke: look up cluster %q: %w", in.Name, err)
	}
	if !exists {
		if err := p.api.create(ctx, in); err != nil {
			return nil, fmt.Errorf("gke: create cluster %q: %w", in.Name, err)
		}
	}
	return p.waitReady(ctx, ref)
}

func (p *provider) ClusterStatus(ctx context.Context, ref planck.ClusterRef) (planck.ClusterStatus, error) {
	st, exists, err := p.api.get(ctx, ref)
	if err != nil {
		return planck.StatusUnknown, err
	}
	if !exists {
		return planck.StatusUnknown, planck.ErrClusterNotFound
	}
	return mapStatus(st.RawStatus), nil
}

func (p *provider) DeleteCluster(ctx context.Context, ref planck.ClusterRef) error {
	if err := p.api.delete(ctx, ref); err != nil {
		return fmt.Errorf("gke: delete cluster %q: %w", ref.Name, err)
	}
	return nil
}

// planCreate resolves a ClusterSpec into a defaults-filled createInput. It is
// the cost/shape decision point: Autopilot is always enabled.
func (p *provider) planCreate(spec planck.ClusterSpec) (createInput, error) {
	if err := validateName(spec.Name); err != nil {
		return createInput{}, err
	}
	loc := spec.Location
	if loc == "" {
		loc = p.defaultLocation
	}
	return createInput{
		Name:      spec.Name,
		Location:  loc,
		Version:   spec.Version,
		Labels:    spec.Labels,
		Autopilot: true,
	}, nil
}

// waitReady polls until the cluster reports Running (returning it with a
// kubeconfig), enters an error state, or ctx expires.
func (p *provider) waitReady(ctx context.Context, ref planck.ClusterRef) (*planck.Cluster, error) {
	for {
		st, exists, err := p.api.get(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("gke: poll cluster %q: %w", ref.Name, err)
		}
		if exists {
			switch mapStatus(st.RawStatus) {
			case planck.StatusRunning:
				return &planck.Cluster{
					Ref:        ref,
					Status:     planck.StatusRunning,
					Endpoint:   st.Endpoint,
					Kubeconfig: buildKubeconfig(ref.Name, st.Endpoint, st.CACert),
				}, nil
			case planck.StatusError:
				return nil, fmt.Errorf("gke: cluster %q entered an error state", ref.Name)
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(p.pollInterval):
		}
	}
}

// mapStatus normalises a GKE native status string to a planck.ClusterStatus.
func mapStatus(raw string) planck.ClusterStatus {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "PROVISIONING", "RECONCILING":
		return planck.StatusProvisioning
	case "RUNNING":
		return planck.StatusRunning
	case "STOPPING":
		return planck.StatusDeleting
	case "ERROR", "DEGRADED":
		return planck.StatusError
	default:
		return planck.StatusUnknown
	}
}

// validateName enforces GKE's cluster-name rules: 1–40 chars, lowercase
// letters/digits/hyphens, starting with a letter and not ending with a hyphen.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("gke: cluster name is required")
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("gke: cluster name %q is longer than %d characters", name, maxNameLen)
	}
	if name[0] < 'a' || name[0] > 'z' {
		return fmt.Errorf("gke: cluster name %q must start with a lowercase letter", name)
	}
	if name[len(name)-1] == '-' {
		return fmt.Errorf("gke: cluster name %q must not end with a hyphen", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return fmt.Errorf("gke: cluster name %q contains invalid character %q", name, string(c))
		}
	}
	return nil
}
