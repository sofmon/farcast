// Package deploy renders TechnoCore's own Kubernetes workload — the Namespace,
// ServiceAccount, RBAC, and Deployment that run the kernel inside an instance
// — as a multi-document YAML apply stream.
//
// Like [fatline/deploy] and [datasphere/deploy] it renders plain YAML rather
// than depending on a Kubernetes client library, and every container carries
// resource requests and drops privilege so the workload is Autopilot-admission
// compliant ([ADR 0003]).
//
// [ADR 0003]: ../../docs/adr/0003-gke-autopilot.md
package deploy

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// Defaults for the TechnoCore workload.
const (
	DefaultNamespace = "farcast-system"
	DefaultName      = "technocore"

	// RequestCPUMilli and RequestMemMiB are the kernel's declared requests,
	// exported for the same reason the other system workloads export theirs:
	// the operator-facing cost estimate is computed from these constants, so
	// the number in a confirmation prompt cannot drift from the number the
	// manifest asks for.
	RequestCPUMilli = 100
	RequestMemMiB   = 128

	// Replicas is one, and this is not a knob.
	//
	// The kernel is a meter with a single ledger. Two replicas would each
	// accrue an independent in-memory total and race to write the same
	// checkpoint, so the instance's spending would become whichever replica
	// wrote last. The ledger's optimistic-concurrency check exists to make
	// that state loud rather than silent, but the fix is not to enter it.
	//
	// A brief gap while the single replica reschedules is survivable
	// precisely because the checkpoint exists: the successor bills the gap it
	// slept through.
	Replicas = 1

	digestMarker = "@sha256:"
)

// Config parameterizes the rendered TechnoCore workload.
type Config struct {
	Namespace string // default DefaultNamespace
	Name      string // default DefaultName
	Image     string // technocore container image, digest-pinned (required)

	Instance string // required, for logs and reports

	// Meter lists the namespaces the kernel meters and may act in. Each one
	// gets a RoleBinding: the ClusterRole below carries the rules, and a
	// RoleBinding grants them in one namespace only, so the kernel can read
	// pods in the namespaces FarCast owns and nowhere else.
	Meter []string

	// The cost limit this instance was installed with. It is passed as
	// arguments rather than environment values because it is not a secret,
	// and because `kubectl describe pod` is where an operator looks first
	// when a kernel is enforcing a limit they do not recognise.
	CostLimit    float64 // required, must be positive
	CostCurrency string  // default "USD"
	CostPeriod   string  // default "monthly"
}

func (c *Config) withDefaults() {
	if c.Namespace == "" {
		c.Namespace = DefaultNamespace
	}
	if c.Name == "" {
		c.Name = DefaultName
	}
	if c.CostCurrency == "" {
		c.CostCurrency = "USD"
	}
	if c.CostPeriod == "" {
		c.CostPeriod = "monthly"
	}
	if len(c.Meter) == 0 {
		c.Meter = []string{c.Namespace}
	}
}

// Render produces the Kubernetes apply stream as multi-document YAML.
func Render(c Config) ([]byte, error) {
	c.withDefaults()
	if c.Image == "" {
		return nil, fmt.Errorf("deploy: technocore image is required")
	}
	if !hasDigest(c.Image) {
		return nil, fmt.Errorf("deploy: technocore image %q is not digest-pinned (want repo@sha256:<64 hex>)", c.Image)
	}
	if c.Instance == "" {
		return nil, fmt.Errorf("deploy: technocore needs the instance name it is the kernel of")
	}
	// A kernel deployed with no limit would meter an instance and never act,
	// which is the one configuration that looks like cost control and is not.
	// Every FarCast instance has a limit; refusing here is how a missing one
	// stays a deployment-time error rather than a silent runtime posture.
	if c.CostLimit <= 0 {
		return nil, fmt.Errorf("deploy: cost limit must be positive, got %v — a kernel with no limit enforces nothing", c.CostLimit)
	}
	for _, ns := range c.Meter {
		if ns == "kube-system" || strings.HasPrefix(ns, "kube-") {
			return nil, fmt.Errorf("deploy: refusing to grant the kernel access to %q; FarCast operates outside the managed namespaces (ADR 0003)", ns)
		}
		if ns == "" {
			return nil, fmt.Errorf("deploy: metered namespace must not be empty")
		}
	}

	data := templateData{
		Namespace:       c.Namespace,
		Name:            c.Name,
		Image:           c.Image,
		Instance:        c.Instance,
		Meter:           c.Meter,
		MeterArg:        strings.Join(c.Meter, ","),
		CostLimit:       c.CostLimit,
		CostCurrency:    c.CostCurrency,
		CostPeriod:      c.CostPeriod,
		Replicas:        Replicas,
		RequestCPUMilli: RequestCPUMilli,
		RequestMemMiB:   RequestMemMiB,
	}
	var buf bytes.Buffer
	if err := workloadTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("deploy: render workload: %w", err)
	}
	return buf.Bytes(), nil
}

func hasDigest(image string) bool {
	_, digest, ok := strings.Cut(image, digestMarker)
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

type templateData struct {
	Meter           []string
	Namespace       string
	Name            string
	Image           string
	Instance        string
	MeterArg        string
	CostCurrency    string
	CostPeriod      string
	CostLimit       float64
	Replicas        int
	RequestCPUMilli int
	RequestMemMiB   int
}

// workloadTemplate renders the kernel.
//
// The Namespace document is byte-identical to FatLine's and datasphered's:
// three modules own their own deployment shape and any of the streams may be
// applied first, so the shared document has to converge rather than fight.
var workloadTemplate = template.Must(template.New("technocore").Parse(`apiVersion: v1
kind: Namespace
metadata:
  name: {{.Namespace}}
  labels:
    app.kubernetes.io/managed-by: farcast
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: technocore
    app.kubernetes.io/managed-by: farcast
---
# The kernel's permissions, as a ClusterRole that is NEVER bound cluster-wide.
#
# A ClusterRole is a rule set, not a grant. Binding it with a RoleBinding
# grants those rules in one namespace only — which is how the kernel reads pods
# in the namespaces FarCast owns and nowhere else. A ClusterRoleBinding here
# would hand it every pod in the cluster, including the managed ones ADR 0003
# puts out of bounds, and nothing in TechnoCore needs that.
#
# The verbs are exactly what technocore/kube calls, and no more:
#   pods              list    — the meter reads what Autopilot bills
#   deployments       list    — the shutdown reads what can be stopped
#   deployments/scale patch   — the only thing the kernel ever writes to a workload
# There is deliberately no watch (the loop polls), no get, no delete, and no
# create of anything at all.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{.Name}}
  labels:
    app.kubernetes.io/name: technocore
    app.kubernetes.io/managed-by: farcast
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["list"]
  - apiGroups: ["apps"]
    resources: ["deployments/scale"]
    verbs: ["patch"]
{{- range .Meter}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{$.Name}}
  namespace: {{.}}
  labels:
    app.kubernetes.io/name: technocore
    app.kubernetes.io/managed-by: farcast
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{$.Name}}
subjects:
  - kind: ServiceAccount
    name: {{$.Name}}
    namespace: {{$.Namespace}}
{{- end}}
---
# The ledger's ConfigMap, and only that one.
#
# Kubernetes cannot restrict create by resourceName — the name is not known
# at authorization time — so create is granted on configmaps in this namespace
# and everything afterwards is pinned to the single object. The kernel can
# therefore make its ledger and maintain it, and cannot read or rewrite any
# other ConfigMap in the namespace it shares with FatLine and datasphered.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{.Name}}-ledger
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: technocore
    app.kubernetes.io/managed-by: farcast
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["{{.Name}}-ledger"]
    verbs: ["get", "update", "patch"]
  # The confirmations the operator pushes: GET ONLY, and the asymmetry is the
  # security property. The kernel cannot author a confirmation, so it cannot
  # fabricate one that would loosen its own guard — which, together with the
  # calibration clamp, makes a confirmed figure untrusted input twice over.
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["{{.Name}}-confirmed"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{.Name}}-ledger
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: technocore
    app.kubernetes.io/managed-by: farcast
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{.Name}}-ledger
subjects:
  - kind: ServiceAccount
    name: {{.Name}}
    namespace: {{.Namespace}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: technocore
    app.kubernetes.io/managed-by: farcast
    # The kernel never stops itself: something has to stay alive to report why
    # everything else stopped (ADR 0009 decisions 6 and 8).
    farcast.sofmon.com/tier: kernel
spec:
  replicas: {{.Replicas}}
  # Recreate, not RollingUpdate, and the reason is arithmetic rather than
  # taste. A rolling update runs the old and new pods together for a few
  # seconds; both would meter the same instance into their own in-memory
  # ledgers and race to write the same checkpoint, and the period's spending
  # would become whichever one wrote last. Recreate makes the handover a gap
  # instead of an overlap, and the checkpoint is what makes a gap harmless.
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: technocore
  template:
    metadata:
      labels:
        app.kubernetes.io/name: technocore
        # The kernel selects pods by this label (technocore/kernel.ManagedBy).
        # It is on the workload above as well, but a controller does not copy
        # its own labels onto the pods it creates — so without it here the
        # meter sees nothing at all and reports $0 forever.
        app.kubernetes.io/managed-by: farcast
        farcast.sofmon.com/tier: kernel
    spec:
      serviceAccountName: {{.Name}}
      # TRUE here, unlike datasphered's false. The kernel's whole job is to
      # talk to the API server, so it needs the projected token — and it holds
      # no key material, so ADR 0008 decision 1's prohibition does not reach
      # it. The token is re-read on every request because the kubelet rotates
      # it while the pod runs.
      automountServiceAccountToken: true
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: technocore
          image: {{.Image}}
          args:
            - serve
            - --instance={{.Instance}}
            - --namespaces={{.MeterArg}}
            - --cost-limit={{.CostLimit}}
            - --cost-currency={{.CostCurrency}}
            - --cost-period={{.CostPeriod}}
          resources:
            requests:
              cpu: {{.RequestCPUMilli}}m
              memory: {{.RequestMemMiB}}Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
      # No volumes. The kernel keeps its state in the ConfigMap above, which
      # survives a restart; node disk would not, and would add a failure mode
      # to the one component that must be able to report why the others are
      # down.
      #
      # No PodDisruptionBudget either, deliberately. A single-replica workload
      # behind minAvailable: 1 makes every node drain hang forever, which
      # would block the auto-upgrades ADR 0003 accepts. The checkpoint is what
      # makes the kernel's own reschedule survivable, so it does not need one.
`))
