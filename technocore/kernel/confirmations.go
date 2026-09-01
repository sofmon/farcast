package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kube"
)

// ConfirmationsVersion is the shape of the confirmations document.
const ConfirmationsVersion = 1

// Where the operator leaves confirmed figures for the kernel to pick up.
const (
	DefaultConfirmationsName = "technocore-confirmed"
	confirmationsKey         = "confirmations.json"
)

// Confirmations is the document the operator's machine writes and the kernel
// reads: the provider's own figures for windows that have closed.
//
// It is a separate object from the checkpoint, written by a different party,
// and the kernel is granted only `get` on it. That asymmetry is the point —
// the kernel cannot author a confirmation, so it cannot fabricate one that
// would loosen its own guard. Combined with [ADR 0009] decision 5's clamp,
// a confirmation is untrusted input twice over: the kernel did not write it,
// and it cannot move the estimate more than the clamp allows.
//
// [ADR 0009]: ../../docs/adr/0009-technocore-kernel-and-cost-metering.md
type Confirmations struct {
	Version       int                 `json:"version"`
	Confirmations []cost.Confirmation `json:"confirmations"`
}

// ConfirmationSource supplies the provider's confirmed figures.
type ConfirmationSource interface {
	// Load returns every confirmation the operator has pushed. An absent
	// document is not an error: an instance whose operator has confirmed
	// nothing runs on `expected` alone, correctly and visibly.
	Load(ctx context.Context) ([]cost.Confirmation, error)
}

// ConfigMapConfirmations reads confirmations from a ConfigMap.
type ConfigMapConfirmations struct {
	Client    ConfigMapClient
	Namespace string
	Name      string
}

// NewConfigMapConfirmations returns a source using the default location.
func NewConfigMapConfirmations(c ConfigMapClient) *ConfigMapConfirmations {
	return &ConfigMapConfirmations{Client: c, Namespace: DefaultCheckpointNamespace, Name: DefaultConfirmationsName}
}

func (s *ConfigMapConfirmations) names() (string, string) {
	ns, name := s.Namespace, s.Name
	if ns == "" {
		ns = DefaultCheckpointNamespace
	}
	if name == "" {
		name = DefaultConfirmationsName
	}
	return ns, name
}

// Load reads the confirmations document.
func (s *ConfigMapConfirmations) Load(ctx context.Context) ([]cost.Confirmation, error) {
	ns, name := s.names()
	cm, err := s.Client.GetConfigMap(ctx, ns, name)
	if errors.Is(err, kube.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kernel: read confirmations: %w", err)
	}
	raw, ok := cm.Data[confirmationsKey]
	if !ok || raw == "" {
		return nil, nil
	}
	var doc Confirmations
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("kernel: decode confirmations: %w", err)
	}
	if doc.Version != ConfirmationsVersion {
		return nil, fmt.Errorf("kernel: unknown confirmations version %d (this build reads %d)",
			doc.Version, ConfirmationsVersion)
	}
	return doc.Confirmations, nil
}

// Marshal renders a confirmations document for the operator side to write.
func Marshal(cs []cost.Confirmation) ([]byte, error) {
	return json.Marshal(Confirmations{Version: ConfirmationsVersion, Confirmations: cs})
}

// RenderConfigMap produces the ConfigMap the operator's machine applies and
// the kernel reads.
//
// It lives beside Load deliberately. The writer is the operator's CLI and the
// reader is an in-cluster process, and the one failure mode that would survive
// every unit test on both sides is the two of them disagreeing about a name —
// the key, the object, the version field. Rendering and parsing from the same
// file makes that disagreement impossible to introduce in one place only.
func RenderConfigMap(namespace, name string, cs []cost.Confirmation) ([]byte, error) {
	if namespace == "" {
		namespace = DefaultCheckpointNamespace
	}
	if name == "" {
		name = DefaultConfirmationsName
	}
	blob, err := Marshal(cs)
	if err != nil {
		return nil, fmt.Errorf("kernel: encode confirmations: %w", err)
	}
	// A literal block scalar carries the JSON verbatim: it is a single line,
	// so no escaping is needed and no quoting dialect can mangle a scope name
	// that happens to contain an apostrophe.
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n")
	fmt.Fprintf(&b, "  name: %s\n  namespace: %s\n", name, namespace)
	fmt.Fprintf(&b, "  labels:\n    app.kubernetes.io/name: technocore\n    app.kubernetes.io/managed-by: farcast\n")
	fmt.Fprintf(&b, "data:\n  %s: |\n    %s\n", confirmationsKey, blob)
	return []byte(b.String()), nil
}

// ConfirmationsKey is the ConfigMap data key the document lives under. It is
// exported because the operator-side command writes the same object the kernel
// reads, and two spellings of one key is a bug that only shows up in
// production.
func ConfirmationsKey() string { return confirmationsKey }

// applyConfirmations feeds any new confirmations into the ledger.
//
// Already-applied windows come back as ErrWindowOverlaps and windows belonging
// to another period as ErrWindowOutsidePeriod; both are expected every tick
// once the operator has pushed anything at all, so neither is reported as a
// fault. Anything else is: a malformed confirmation is the operator's data
// being wrong, and the kernel should say so rather than skip it in silence.
func (r *Reconciler) applyConfirmations(ctx context.Context, rep *Report) error {
	if r.Confirmations == nil {
		return nil
	}
	cs, err := r.Confirmations.Load(ctx)
	if err != nil {
		return err
	}
	for _, c := range cs {
		d, err := r.Ledger.Confirm(c)
		switch {
		case errors.Is(err, cost.ErrWindowOverlaps), errors.Is(err, cost.ErrWindowOutsidePeriod):
			continue
		case err != nil:
			return fmt.Errorf("kernel: confirmation for %s: %w", c.Start.Format("2006-01-02"), err)
		}
		rep.ConfirmationsApplied++
		if d != nil {
			rep.ConfirmationsRefused++
		}
	}
	return nil
}
