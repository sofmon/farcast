// Package translate turns a parsed ./farcast manifest into the Kubernetes
// workloads that run it.
//
// It is the 4.2 half of Planck: the module provisions a cluster and then
// translates manifests into workloads, and does no watching, scaling or cost
// enforcement — those are TechnoCore's ([`../../technocore/README.md`]).
//
// Like [fatline/deploy], [datasphere/deploy] and [technocore/deploy] it renders
// plain YAML rather than depending on a Kubernetes client library, and every
// container it emits is Autopilot-admission compliant ([ADR 0003]).
//
// It is an exported package rather than planck/internal/translator, which is
// what the 1.2 roadmap sketched: the operator CLI has to render these workloads
// and Go's internal rule would put them out of its reach. Every other module's
// deploy package settled on the same shape.
//
// [ADR 0003]: ../../docs/adr/0003-gke-autopilot.md
package translate

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sofmon/farcast/manifest/parser"
)

// Defaults for a translated workload.
const (
	// SystemNamespace is where FarCast's own components live, and therefore
	// where an application's egress and storage traffic is allowed to go.
	SystemNamespace = "farcast-system"

	// FatLineService and FatLineEgressPort are the forward proxy an
	// application's outbound traffic must use. Nothing else is reachable:
	// the NetworkPolicy denies it and FatLine's allowlist enforces the hosts
	// (ADR 0005).
	FatLineService    = "fatline"
	FatLineEgressPort = 3128

	// StorageService and StoragePort are the keyholder's data path.
	StorageService       = "datasphered"
	StoragePort          = 8443
	StorageStatusService = "datasphered-status"
	StorageStatusPort    = 8444

	// RequestCPUMilli and RequestMemMiB are the conservative starting
	// requests every translated application gets, matching what FarCast's own
	// components ask for.
	//
	// "Conservative" is PLAN 4.2's word and it is about cost, not headroom:
	// Autopilot bills requests, TechnoCore adapts them at 5.2, and a first
	// deploy that is too small fails visibly while one that is too large bills
	// silently. On a cluster without bursting support Autopilot raises these
	// to its own 250m/512Mi floor — the operator sees that in the cost report
	// rather than here.
	RequestCPUMilli = 100
	RequestMemMiB   = 128

	// DefaultPort is the container port a translated app is assumed to serve
	// on, and the port its Service publishes.
	DefaultPort = 8080
)

// Config parameterizes a translation.
type Config struct {
	// Manifest is the parsed ./farcast document.
	Manifest parser.Manifest

	// Namespace defaults to the manifest's top-level name. It is separate
	// from that name so a caller can deploy the same manifest twice under
	// different namespaces without editing the repository.
	Namespace string

	// Images maps each app's name to its digest-pinned image reference. Every
	// app in the manifest must have one: a translation that guessed, or that
	// emitted a tag, would deploy something other than what was built
	// (ADR 0007 decision 4).
	Images map[string]string

	// Instance is the instance these workloads belong to, recorded as a label
	// so a console or a bill reads as one recognisable set of resources.
	Instance string

	// StorageScope is the DataSphere scope applications are given. Empty
	// means storage is not wired up, and the SDK will report ErrStorageSealed
	// rather than reaching a keyholder it was not told about.
	StorageScope string

	// StorageCAPEM is the instance CA certificate an application uses to
	// verify the keyholder. It is a certificate, not a key: it goes in a
	// ConfigMap, and putting it anywhere more guarded would imply it is
	// secret when it is published in every TLS handshake.
	StorageCAPEM []byte

	// StorageServerName pins the identity the keyholder must present,
	// separately from the address used to reach it (see sdk/go's
	// FARCAST_STORAGE_SERVER_NAME).
	StorageServerName string
}

func (c *Config) withDefaults() {
	if c.Namespace == "" {
		c.Namespace = c.Manifest.Name
	}
}

// Render produces the Kubernetes apply stream for a manifest: one Namespace,
// then a ConfigMap, Deployment, Service and NetworkPolicy for each app.
func Render(c Config) ([]byte, error) {
	c.withDefaults()
	if c.Manifest.Name == "" {
		return nil, fmt.Errorf("translate: the manifest has no name")
	}
	if len(c.Manifest.Apps) == 0 {
		return nil, fmt.Errorf("translate: manifest %q declares no apps", c.Manifest.Name)
	}
	if err := validateName(c.Namespace); err != nil {
		return nil, fmt.Errorf("translate: namespace %q: %w", c.Namespace, err)
	}
	if c.Namespace == SystemNamespace {
		// FarCast's own components live there, and an application namespace
		// is deleted wholesale when its deployment is removed.
		return nil, fmt.Errorf("translate: refusing to deploy applications into %q, which belongs to FarCast itself", SystemNamespace)
	}
	if strings.HasPrefix(c.Namespace, "kube-") {
		return nil, fmt.Errorf("translate: refusing to deploy into the managed namespace %q (ADR 0003)", c.Namespace)
	}

	data := templateData{
		Namespace:            c.Namespace,
		Deployment:           c.Manifest.Name,
		Instance:             c.Instance,
		SystemNamespace:      SystemNamespace,
		FatLineService:       FatLineService,
		FatLineEgressPort:    FatLineEgressPort,
		StorageService:       StorageService,
		StoragePort:          StoragePort,
		StorageStatusService: StorageStatusService,
		StorageStatusPort:    StorageStatusPort,
		StorageScope:         c.StorageScope,
		StorageServerName:    c.StorageServerName,
		StorageCA:            indentPEM(c.StorageCAPEM),
		HasStorage:           c.StorageScope != "" && len(c.StorageCAPEM) > 0,
		RequestCPUMilli:      RequestCPUMilli,
		RequestMemMiB:        RequestMemMiB,
		Port:                 DefaultPort,
	}

	seen := map[string]bool{}
	for _, app := range c.Manifest.Apps {
		if err := validateName(app.Name); err != nil {
			return nil, fmt.Errorf("translate: app %q: %w", app.Name, err)
		}
		if seen[app.Name] {
			return nil, fmt.Errorf("translate: app %q appears twice in the manifest", app.Name)
		}
		seen[app.Name] = true

		image := c.Images[app.Name]
		if image == "" {
			return nil, fmt.Errorf("translate: no image for app %q; every app must be built before it is translated", app.Name)
		}
		if !hasDigest(image) {
			return nil, fmt.Errorf("translate: image %q for app %q is not digest-pinned (want repo@sha256:<64 hex>)", image, app.Name)
		}
		data.Apps = append(data.Apps, appData{Name: app.Name, Image: image})
	}

	var buf bytes.Buffer
	if err := workloadTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("translate: render workloads: %w", err)
	}
	return buf.Bytes(), nil
}

// validateName enforces the DNS-label shape Kubernetes requires for a
// namespace or a workload name. The manifest parser validates app names for
// its own purposes; this validates them for the thing they become.
func validateName(s string) error {
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	if len(s) > 63 {
		return fmt.Errorf("must be at most 63 characters")
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i != 0 && i != len(s)-1:
		default:
			return fmt.Errorf("must be a DNS label: lowercase letters, digits and interior hyphens")
		}
	}
	return nil
}

func hasDigest(image string) bool {
	_, digest, ok := strings.Cut(image, "@sha256:")
	if !ok || len(digest) != 64 {
		return false
	}
	for i := range len(digest) {
		switch c := digest[i]; {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// indentPEM lays a certificate out as a YAML block scalar body.
func indentPEM(pem []byte) string {
	if len(pem) == 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(pem), "\n"), "\n")
	for i, l := range lines {
		lines[i] = "    " + l
	}
	return strings.Join(lines, "\n")
}

type appData struct {
	Name  string
	Image string
}

type templateData struct {
	Apps                 []appData
	Namespace            string
	Deployment           string
	Instance             string
	SystemNamespace      string
	FatLineService       string
	StorageService       string
	StorageStatusService string
	StorageScope         string
	StorageServerName    string
	StorageCA            string
	HasStorage           bool
	FatLineEgressPort    int
	StoragePort          int
	StorageStatusPort    int
	RequestCPUMilli      int
	RequestMemMiB        int
	Port                 int
}
