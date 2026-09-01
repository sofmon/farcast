// Package deploy renders FatLine's own Kubernetes workload — the Namespace,
// mTLS Secret, Deployment, and Service that run FatLine inside an instance — as
// a multi-document YAML apply stream. FatLine owns the shape of how it is
// deployed; `farcast connect` (2.3) pipes the output to `kubectl apply -f -`.
//
// It is the one-off precursor to Planck's general manifest→workload translator
// (4.2). It deliberately renders plain YAML rather than depending on a
// Kubernetes client library — the operator-side toolchain stays minimal-deps
// (the CLI uses kubectl, ADR 0006). Every container carries resource requests
// and drops privilege, so the workload is GKE Autopilot-admission-compliant
// (ADR 0003).
package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"text/template"
)

// Carrier is how the operator's tunnel traffic reaches FatLine.
type Carrier string

const (
	// CarrierLoadBalancer fronts FatLine with a public, mTLS-gated L4 passthrough
	// load balancer (the default 2.3 point of presence, ADR 0005).
	CarrierLoadBalancer Carrier = "LoadBalancer"
	// CarrierClusterIP exposes FatLine only inside the cluster (the control-plane
	// port-forward fallback's service type; bound in a later phase).
	CarrierClusterIP Carrier = "ClusterIP"
)

// Defaults for the FatLine workload.
const (
	DefaultNamespace  = "farcast-system"
	DefaultName       = "fatline"
	DefaultTunnelPort = 8443
	DefaultEgressPort = 3128
	secretName        = "fatline-mtls"
	tlsMountPath      = "/etc/fatline/tls"

	// DefaultReplicas is two for the same reason datasphered runs two
	// (ADR 0008 decision 6, ADR 0009 decision 11), and the reason is not
	// throughput. Every unseal push — and every keeper reseed at 5.4 — rides
	// this tunnel, so a single replica makes recovery time a function of
	// FatLine's own reschedule during exactly the node-drain window that
	// sealed storage in the first place. The marginal replica is ~$4/month
	// against an instance floor of roughly $73; the alternative is an
	// instance that cannot be unsealed while it keeps billing.
	//
	// Not a tuning knob. Config.Replicas exists so tests can render one, not
	// so a deployment can quietly go back to being unrecoverable.
	DefaultReplicas = 2

	// RequestCPUMilli and RequestMemMiB are the container's declared resource
	// requests, and they are exported because Autopilot bills requests: the
	// operator-facing cost estimate is computed from these very constants
	// (technocore/pricing), so the number quoted in a confirmation prompt
	// cannot drift from the number the manifest actually asks for.
	RequestCPUMilli = 100
	RequestMemMiB   = 128
)

// Config parameterizes the rendered FatLine workload. The Secret carries the CA
// *certificate* (to verify operator clients) plus FatLine's own server leaf+key
// — never the CA private key, which stays on the operator's machine.
type Config struct {
	Namespace  string  // default DefaultNamespace
	Name       string  // default DefaultName
	Image      string  // FatLine container image (required)
	Carrier    Carrier // default CarrierLoadBalancer
	TunnelPort int     // default DefaultTunnelPort
	EgressPort int     // default DefaultEgressPort
	Replicas   int     // default DefaultReplicas

	// StreamRoutes are the in-instance services the operator may reach
	// through the tunnel, each as name=host:port[=ordinals]. They are fixed
	// here, at deploy time, because a caller names a route and never an
	// address — that is what keeps an operator credential from becoming a
	// general port-forward into the cluster.
	StreamRoutes []string

	CACertPEM     []byte
	ServerCertPEM []byte
	ServerKeyPEM  []byte
}

func (c *Config) withDefaults() {
	if c.Namespace == "" {
		c.Namespace = DefaultNamespace
	}
	if c.Name == "" {
		c.Name = DefaultName
	}
	if c.Carrier == "" {
		c.Carrier = CarrierLoadBalancer
	}
	if c.TunnelPort == 0 {
		c.TunnelPort = DefaultTunnelPort
	}
	if c.EgressPort == 0 {
		c.EgressPort = DefaultEgressPort
	}
	if c.Replicas == 0 {
		c.Replicas = DefaultReplicas
	}
}

// Render produces the Kubernetes apply stream (Namespace, Secret, Deployment,
// PodDisruptionBudget, Service) as multi-document YAML for `kubectl apply -f -`.
func Render(c Config) ([]byte, error) {
	c.withDefaults()
	if c.Image == "" {
		return nil, errors.New("deploy: FatLine image is required")
	}
	if len(c.CACertPEM) == 0 || len(c.ServerCertPEM) == 0 || len(c.ServerKeyPEM) == 0 {
		return nil, errors.New("deploy: incomplete mTLS material (need CA cert + server leaf+key)")
	}
	if c.Carrier != CarrierLoadBalancer && c.Carrier != CarrierClusterIP {
		return nil, fmt.Errorf("deploy: unknown carrier %q", c.Carrier)
	}
	if c.Replicas < 1 {
		return nil, fmt.Errorf("deploy: replicas must be at least 1, got %d", c.Replicas)
	}

	data := templateData{
		Namespace:       c.Namespace,
		Name:            c.Name,
		Image:           c.Image,
		Carrier:         string(c.Carrier),
		TunnelPort:      c.TunnelPort,
		EgressPort:      c.EgressPort,
		Replicas:        c.Replicas,
		RequestCPUMilli: RequestCPUMilli,
		RequestMemMiB:   RequestMemMiB,
		SecretName:      secretName,
		MountPath:       tlsMountPath,
		CACert:          base64.StdEncoding.EncodeToString(c.CACertPEM),
		ServerCert:      base64.StdEncoding.EncodeToString(c.ServerCertPEM),
		ServerKey:       base64.StdEncoding.EncodeToString(c.ServerKeyPEM),
		StreamRoutes:    c.StreamRoutes,
		MTLSHash:        mtlsHash(c.CACertPEM, c.ServerCertPEM, c.ServerKeyPEM),
	}
	var buf bytes.Buffer
	if err := workloadTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("deploy: render workload: %w", err)
	}
	return buf.Bytes(), nil
}

// mtlsHash fingerprints the mTLS material so a change to it reaches the running
// process.
//
// Kubernetes updates a mounted Secret in place, and FatLine reads its
// certificate once at start-up — so rotating the material while the Deployment
// spec stays byte-identical would update the Secret, restart nothing, and let
// `kubectl rollout status` report success against a Pod still serving the old
// certificate. Carrying the fingerprint in the pod template makes any change to
// the material a spec change, which is what actually triggers a rolling
// restart.
func mtlsHash(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

type templateData struct {
	StreamRoutes []string
	Namespace    string
	Name         string
	Image        string
	Carrier      string
	TunnelPort   int
	EgressPort   int
	Replicas     int
	SecretName   string
	MountPath    string
	MTLSHash     string
	CACert       string
	ServerCert   string
	ServerKey    string

	// Rendered from the exported constants rather than written into the
	// template, so the cost estimate and the manifest quote one number.
	RequestCPUMilli int
	RequestMemMiB   int
}

// workloadTemplate renders an Autopilot-compliant FatLine workload: resource
// requests on the container, no privilege, runs as non-root, drops all caps.
// FatLine terminates mTLS in userspace, so only the tunnel port is exposed; the
// egress proxy is in-cluster only (apps reach it via the SDK env var, 4.2).
var workloadTemplate = template.Must(template.New("fatline").Parse(`apiVersion: v1
kind: Namespace
metadata:
  name: {{.Namespace}}
  labels:
    app.kubernetes.io/managed-by: farcast
---
apiVersion: v1
kind: Secret
metadata:
  name: {{.SecretName}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: fatline
type: Opaque
data:
  ca.crt: {{.CACert}}
  server.crt: {{.ServerCert}}
  server.key: {{.ServerKey}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: fatline
    app.kubernetes.io/managed-by: farcast
    # Classified last-to-die (ADR 0008, ADR 0009 decision 6). TechnoCore's
    # cost shutdown stops applications only: stopping the tunnel would leave
    # storage impossible to unseal while the instance carried on billing.
    farcast.sofmon.com/tier: system
spec:
  replicas: {{.Replicas}}
  # Two by default (ADR 0009 decision 11). maxUnavailable defaults to 25%,
  # which rounds DOWN to 0 at two replicas, and maxSurge rounds UP to 1 — so a
  # certificate rotation or image bump adds a pod before it removes one and the
  # tunnel never goes to zero during a rollout. Stated because the property is
  # a consequence of the replica count, and would silently disappear at one.
  selector:
    matchLabels:
      app.kubernetes.io/name: fatline
  template:
    metadata:
      labels:
        app.kubernetes.io/name: fatline
        # On the pod too, not only the Deployment: TechnoCore reads pods to
        # meter and workloads to scale, and a label on one of the two is a
        # classification with a hole in it.
        farcast.sofmon.com/tier: system
      annotations:
        # Fingerprint of the mounted mTLS material. It exists to make a
        # certificate rotation restart the Pod: without it the Deployment spec
        # would be unchanged, apply would be a no-op, and the old certificate
        # would keep serving while the rollout reported success.
        farcast.sofmon.com/mtls-hash: {{.MTLSHash}}
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        # The mTLS material is mounted 0440 and owned by this group. Without
        # fsGroup the kubelet leaves the secret owned by root, and FatLine —
        # which runs as 65532 and must not run as root — cannot read the key it
        # was given. (Caught by the first live deploy: permission denied on
        # server.crt, crash-looping.)
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      # ScheduleAnyway, matching datasphered's constraint and its reasoning: on
      # Autopilot a hard DoNotSchedule leaves the second replica Pending when
      # only one node fits, which is the single-replica outage this constraint
      # was added to prevent. Co-located replicas still survive a pod OOM and a
      # rollout; a Pending replica survives nothing.
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: fatline
      containers:
        - name: fatline
          image: {{.Image}}
          args:
            - --tunnel-listen=:{{.TunnelPort}}
            - --egress-listen=:{{.EgressPort}}
            - --cert={{.MountPath}}/server.crt
            - --key={{.MountPath}}/server.key
            - --ca={{.MountPath}}/ca.crt
{{- range .StreamRoutes}}
            - --stream-route={{.}}
{{- end}}
          ports:
            - name: tunnel
              containerPort: {{.TunnelPort}}
            - name: egress
              containerPort: {{.EgressPort}}
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
          volumeMounts:
            - name: mtls
              mountPath: {{.MountPath}}
              readOnly: true
      volumes:
        - name: mtls
          secret:
            secretName: {{.SecretName}}
            # 0440: readable by the running user's group, never world-readable,
            # never writable. Paired with fsGroup above — 0400 would be
            # root-only and the non-root container could not read it.
            defaultMode: 288
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: fatline
    app.kubernetes.io/managed-by: farcast
spec:
  # The counterpart to datasphered's PDB, and useless without it — a drain that
  # respects storage's budget but takes the tunnel leaves an instance that is
  # unsealable rather than sealed. minAvailable: 1 makes a node drain wait for
  # a replacement instead of taking the last tunnel. Like datasphered's, it
  # constrains voluntary disruption only: it does not survive a full pool walk
  # or a zonal loss.
  minAvailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: fatline
---
apiVersion: v1
kind: Service
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: fatline
    app.kubernetes.io/managed-by: farcast
spec:
  type: {{.Carrier}}
  selector:
    app.kubernetes.io/name: fatline
  ports:
    - name: tunnel
      port: {{.TunnelPort}}
      targetPort: tunnel
`))
