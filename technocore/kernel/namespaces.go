package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/sofmon/farcast/technocore/kube"
)

// NamespacesVersion is the shape of the metered-namespace document.
const NamespacesVersion = 1

// Where the operator lists the namespaces the kernel should meter.
const (
	DefaultNamespacesName = "technocore-namespaces"
	namespacesKey         = "namespaces.json"
)

// Namespaces is the document the operator's machine writes when it deploys an
// application, and the kernel reads on every tick.
//
// It exists so that deploying an application does not restart the kernel. The
// alternative — re-rendering the workload with a longer --namespaces argument
// — would tear down the meter on every deploy, and the kernel is deliberately
// `Recreate` with a single replica, so that is a real gap in cost enforcement
// at exactly the moment new spending starts.
//
// The kernel is granted `get` on this object and never `update`: a kernel that
// could edit its own metering scope could narrow it, and a narrowed scope
// looks identical to an instance that is not spending anything.
type Namespaces struct {
	Version int      `json:"version"`
	Meter   []string `json:"meter"`
}

// NamespaceSource supplies the namespaces to meter beyond the configured ones.
type NamespaceSource interface {
	// Load returns the namespaces the operator has asked for. An absent
	// document is not an error — a fresh instance has no applications.
	Load(ctx context.Context) ([]string, error)
}

// ConfigMapNamespaces reads the metered-namespace list from a ConfigMap.
type ConfigMapNamespaces struct {
	Client    ConfigMapClient
	Namespace string
	Name      string
}

// NewConfigMapNamespaces returns a source using the default location.
func NewConfigMapNamespaces(c ConfigMapClient) *ConfigMapNamespaces {
	return &ConfigMapNamespaces{Client: c, Namespace: DefaultCheckpointNamespace, Name: DefaultNamespacesName}
}

func (s *ConfigMapNamespaces) names() (string, string) {
	ns, name := s.Namespace, s.Name
	if ns == "" {
		ns = DefaultCheckpointNamespace
	}
	if name == "" {
		name = DefaultNamespacesName
	}
	return ns, name
}

// Load reads the metered-namespace document.
func (s *ConfigMapNamespaces) Load(ctx context.Context) ([]string, error) {
	ns, name := s.names()
	cm, err := s.Client.GetConfigMap(ctx, ns, name)
	if errors.Is(err, kube.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kernel: read the metered namespaces: %w", err)
	}
	raw, ok := cm.Data[namespacesKey]
	if !ok || raw == "" {
		return nil, nil
	}
	var doc Namespaces
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("kernel: decode the metered namespaces: %w", err)
	}
	if doc.Version != NamespacesVersion {
		return nil, fmt.Errorf("kernel: unknown metered-namespace version %d (this build reads %d)",
			doc.Version, NamespacesVersion)
	}
	return doc.Meter, nil
}

// MarshalNamespaces renders the document for the operator side to write.
func MarshalNamespaces(meter []string) ([]byte, error) {
	return json.Marshal(Namespaces{Version: NamespacesVersion, Meter: meter})
}

// NamespacesKey is the ConfigMap data key the document lives under, exported
// so the writer and the reader cannot disagree about it.
func NamespacesKey() string { return namespacesKey }

// RenderNamespacesConfigMap produces the ConfigMap the operator applies.
func RenderNamespacesConfigMap(namespace, name string, meter []string) ([]byte, error) {
	if namespace == "" {
		namespace = DefaultCheckpointNamespace
	}
	if name == "" {
		name = DefaultNamespacesName
	}
	blob, err := MarshalNamespaces(meter)
	if err != nil {
		return nil, fmt.Errorf("kernel: encode the metered namespaces: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n")
	fmt.Fprintf(&b, "  name: %s\n  namespace: %s\n", name, namespace)
	fmt.Fprintf(&b, "  labels:\n    app.kubernetes.io/name: technocore\n    app.kubernetes.io/managed-by: farcast\n")
	fmt.Fprintf(&b, "data:\n  %s: |\n    %s\n", namespacesKey, blob)
	return []byte(b.String()), nil
}

// meteredNamespaces is the set this tick should read: the configured ones plus
// whatever the operator has since added, de-duplicated and ordered so a report
// is stable between ticks.
//
// The configured list is never dropped. A discovery document that omitted
// farcast-system would otherwise stop the instance's own components being
// metered, and under-reporting is the failure direction this package exists to
// avoid.
func (r *Reconciler) meteredNamespaces(ctx context.Context) ([]string, error) {
	set := map[string]bool{}
	for _, ns := range r.Namespaces {
		set[ns] = true
	}
	if r.Discover != nil {
		found, err := r.Discover.Load(ctx)
		if err != nil {
			return nil, err
		}
		for _, ns := range found {
			if ns = strings.TrimSpace(ns); ns != "" {
				set[ns] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out, nil
}
