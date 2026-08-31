// Package deploy renders `datasphered`'s Kubernetes workload — the Namespace,
// mTLS Secret, StatefulSet, PodDisruptionBudget, and three Services that run
// the in-cluster keyholder — as a multi-document YAML apply stream.
//
// It is the DataSphere twin of [fatline/deploy]: same shape, same rendering
// discipline (plain YAML through text/template rather than a Kubernetes client
// library, so the operator-side toolchain stays minimal-deps — ADR 0006), same
// Autopilot-admission compliance (resource requests on every container, no
// privilege — ADR 0003). What differs is what the workload holds, and every
// difference below is [ADR 0008] in code.
//
// The three rules that shape this file, and that a reviewer should check first:
//
//   - **No volumes of any kind** (decision 1). An emptyDir is node disk and a
//     projected ServiceAccount token is a volume too, so the server leaf, its
//     key, and the CA certificate reach the process through `env` +
//     `secretKeyRef`, and `automountServiceAccountToken` is false.
//   - **A sealed replica is a normal, expected state** (decisions 5 and 7). It
//     is never Ready, it never crash-loops, and it must still be reachable —
//     which is why there are three Services rather than one and why two of them
//     publish not-ready addresses.
//   - **Two replicas and a PDB** (decision 6), because they cost ~$4/month and
//     survive the common events: a single-pod OOM, one node's auto-repair, a
//     rollout, an eviction under bin-packing. They do not survive a full pool
//     walk or a zonal loss, and the ADR says so rather than implying otherwise.
//
// [ADR 0008]: ../../docs/adr/0008-in-cluster-key-delivery.md
// [fatline/deploy]: ../../fatline/deploy
package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"text/template"
)

// Defaults for the `datasphered` workload.
const (
	DefaultNamespace = "farcast-system"
	DefaultName      = "datasphered"
	// DefaultReplicas is ADR 0008 decision 6's two, not a tuning knob with a
	// convenient default: one replica seals the instance on every routine
	// Autopilot restart, and the second is what makes the common events
	// survivable.
	DefaultReplicas = 2
	// DefaultDataPort carries the SDK's storage calls, mTLS-terminated in
	// userspace.
	DefaultDataPort = 8443
	// DefaultStatusPort carries readiness, liveness, and the SDK's pre-attempt
	// Status() seam.
	DefaultStatusPort = 8444
	// DefaultUnsealPort receives the operator's (later the keeper's) bundle
	// push over the FatLine tunnel — decision 4.
	DefaultUnsealPort = 9443
	// DefaultProvider is the cloud storage adapter the keyholder opens.
	DefaultProvider = "gcs"

	secretName = "datasphered-mtls"
	// digestMarker pins the image by content. ADR 0008 decision 1: deployed
	// pinned by digest.
	digestMarker = "@sha256:"
)

// Config parameterizes the rendered `datasphered` workload.
//
// It carries transport material only. The Secret holds the CA *certificate* (to
// verify the operator's and keepers' client leaves) plus the server leaf+key —
// the same concession FatLine already makes, and for the same reason: a
// rotatable transport key whose compromise exposes one listener's future
// sessions. No keyring entry appears here, in the Secret, or anywhere else in
// the rendered stream; the derived per-scope bundle arrives at runtime over
// UnsealPort and lives only in memory (ADR 0008, decisions 1 and 2).
type Config struct {
	Namespace  string // default DefaultNamespace
	Name       string // default DefaultName
	Image      string // datasphered container image, digest-pinned (required)
	Replicas   int    // default DefaultReplicas
	DataPort   int    // default DefaultDataPort
	StatusPort int    // default DefaultStatusPort
	UnsealPort int    // default DefaultUnsealPort

	// The storage target the keyholder serves. It is passed as arguments
	// rather than environment values because these are not secrets and
	// because `kubectl describe pod` is where an operator looks first when a
	// keyholder is pointed at the wrong bucket.
	Instance string // required
	Bucket   string // required
	Provider string // default "gcs"
	Project  string
	Location string

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
	if c.Replicas == 0 {
		c.Replicas = DefaultReplicas
	}
	if c.DataPort == 0 {
		c.DataPort = DefaultDataPort
	}
	if c.StatusPort == 0 {
		c.StatusPort = DefaultStatusPort
	}
	if c.UnsealPort == 0 {
		c.UnsealPort = DefaultUnsealPort
	}
	if c.Provider == "" {
		c.Provider = DefaultProvider
	}
}

// Render produces the Kubernetes apply stream (Namespace, Secret, StatefulSet,
// PodDisruptionBudget, and the data/status/unseal Services) as multi-document
// YAML for `kubectl apply -f -`.
func Render(c Config) ([]byte, error) {
	c.withDefaults()
	if c.Image == "" {
		return nil, errors.New("deploy: datasphered image is required")
	}
	// A tag is a mutable pointer the registry's owner can re-aim. The one
	// in-cluster component that holds key material is the last place to accept
	// "whatever :latest means today", so the pin is enforced here rather than
	// left to the caller's discipline (ADR 0008 decision 1).
	if !hasDigest(c.Image) {
		return nil, fmt.Errorf("deploy: datasphered image %q is not digest-pinned (want repo@sha256:<64 hex>)", c.Image)
	}
	if len(c.CACertPEM) == 0 || len(c.ServerCertPEM) == 0 || len(c.ServerKeyPEM) == 0 {
		return nil, errors.New("deploy: incomplete mTLS material (need CA cert + server leaf+key)")
	}
	// A keyholder with no bucket would start, pass its probes and refuse every
	// write, so the omission is caught here rather than in the cluster.
	if c.Instance == "" || c.Bucket == "" {
		return nil, errors.New("deploy: datasphered needs both an instance and a bucket to serve")
	}
	if c.Replicas < 1 {
		return nil, fmt.Errorf("deploy: replicas must be at least 1, got %d", c.Replicas)
	}
	if c.DataPort == c.StatusPort || c.DataPort == c.UnsealPort || c.StatusPort == c.UnsealPort {
		return nil, fmt.Errorf("deploy: data (%d), status (%d) and unseal (%d) ports must differ", c.DataPort, c.StatusPort, c.UnsealPort)
	}

	data := templateData{
		Instance:      c.Instance,
		Bucket:        c.Bucket,
		Provider:      c.Provider,
		Project:       c.Project,
		Location:      c.Location,
		Namespace:     c.Namespace,
		Name:          c.Name,
		StatusService: c.Name + "-status",
		UnsealService: c.Name + "-unseal",
		Image:         c.Image,
		Replicas:      c.Replicas,
		DataPort:      c.DataPort,
		StatusPort:    c.StatusPort,
		UnsealPort:    c.UnsealPort,
		SecretName:    secretName,
		CACert:        base64.StdEncoding.EncodeToString(c.CACertPEM),
		ServerCert:    base64.StdEncoding.EncodeToString(c.ServerCertPEM),
		ServerKey:     base64.StdEncoding.EncodeToString(c.ServerKeyPEM),
		MTLSHash:      mtlsHash(c.CACertPEM, c.ServerCertPEM, c.ServerKeyPEM),
	}
	var buf bytes.Buffer
	if err := workloadTemplate.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("deploy: render workload: %w", err)
	}
	return buf.Bytes(), nil
}

// hasDigest reports whether an image reference is pinned by content digest.
// Lexical, not cryptographic: it proves the reference names a digest, not that
// the digest names the intended image.
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

// mtlsHash fingerprints the mTLS material so a change to it reaches the running
// process.
//
// Kubernetes updates a Secret in place — through `env` exactly as through a
// mounted volume, and in the env case the container never sees the new value at
// all — and `datasphered` reads its certificate once at start-up. Rotating the
// material while the StatefulSet spec stayed byte-identical would update the
// Secret, restart nothing, and let `kubectl rollout status` report success
// against Pods still serving the old certificate. Carrying the fingerprint in
// the pod template makes any change to the material a spec change, which is
// what actually triggers a rolling restart.
func mtlsHash(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

type templateData struct {
	Instance      string
	Bucket        string
	Provider      string
	Project       string
	Location      string
	Namespace     string
	Name          string
	StatusService string
	UnsealService string
	Image         string
	Replicas      int
	DataPort      int
	StatusPort    int
	UnsealPort    int
	SecretName    string
	MTLSHash      string
	CACert        string
	ServerCert    string
	ServerKey     string
}

// workloadTemplate renders the keyholder. The Namespace document is
// deliberately byte-identical to FatLine's: both modules own their own
// deployment shape and either stream may be applied first, so the shared
// document has to converge rather than fight — identical content makes the
// second apply a no-op instead of a field-ownership tug-of-war.
var workloadTemplate = template.Must(template.New("datasphered").Parse(`apiVersion: v1
kind: Namespace
metadata:
  name: {{.Namespace}}
  labels:
    app.kubernetes.io/managed-by: farcast
---
# The keyholder's own cloud identity.
#
# It gets a dedicated ServiceAccount rather than the namespace default so that
# the bucket grant names THIS workload: a binding on the default account would
# hand the instance's storage to anything that happens to run in the namespace.
#
# No token is mounted (automountServiceAccountToken is false below). On GKE the
# metadata server identifies a Pod from its ServiceAccount out of band, so
# Workload Identity resolves without a projected token — which is what lets
# ADR 0008 decision 1's "no volumes of any kind" hold while decision 8's
# cloud-side bucket credential still works.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: {{.Name}}
    app.kubernetes.io/managed-by: farcast
---
apiVersion: v1
kind: Secret
metadata:
  name: {{.SecretName}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: datasphered
# Transport material only: the CA *certificate* that verifies operator and
# keeper client leaves, plus this listener's own server leaf and key. The CA
# private key stays on the operator's machine, and no keyring entry — master or
# derived — is ever written here. A Secret is etcd, on the cloud's machines, in
# their backups: that is tolerable for a rotatable transport key and is exactly
# what ADR 0008 exists to forbid for the keyring.
type: Opaque
data:
  ca.crt: {{.CACert}}
  server.crt: {{.ServerCert}}
  server.key: {{.ServerKey}}
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: datasphered
    app.kubernetes.io/managed-by: farcast
spec:
  replicas: {{.Replicas}}
  # The headless Service below governs this set's DNS. It is what gives each
  # replica a stable per-ordinal name for the operator to unseal.
  serviceName: {{.UnsealService}}
  # Parallel is mandatory, not a preference. Under the default OrderedReady the
  # controller creates pod-0 and waits for it to become Ready before creating
  # pod-1 — but a fresh replica comes back SEALED and a sealed replica fails
  # readiness by design (ADR 0008 decisions 5 and 7). OrderedReady would
  # therefore never create pod-1, pinning the fleet at one replica permanently
  # and silently deleting decision 6's whole benefit. Parallel affects creation
  # and scaling only; updates stay ordered, which is what the note on
  # updateStrategy relies on.
  podManagementPolicy: Parallel
  # partition: 0 means every ordinal is eligible for update. It is the default,
  # stated so that setting it to anything else is a deliberate act. Note the
  # interaction this produces, which is a feature: a rolling update replaces the
  # highest ordinal first and waits for Ready, so the replacement comes back
  # sealed and the rollout STOPS there. A redeploy can never walk the fleet down
  # to zero unsealed replicas on its own — it parks, holding the last loaded
  # replica, until the operator unseals the new one.
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      partition: 0
  # 0, stated rather than defaulted: readiness here means "unsealed", so any
  # settle window would be time added to a gate only a human can open.
  minReadySeconds: 0
  selector:
    matchLabels:
      app.kubernetes.io/name: datasphered
  template:
    metadata:
      labels:
        app.kubernetes.io/name: datasphered
      annotations:
        # Fingerprint of the mTLS material. It exists to make a certificate
        # rotation restart the Pods: without it the StatefulSet spec would be
        # unchanged, apply would be a no-op, and the old certificate would keep
        # serving while the rollout reported success.
        farcast.sofmon.com/mtls-hash: {{.MTLSHash}}
    spec:
      # ADR 0008 decision 1 permits no volumes of any kind, and a projected
      # ServiceAccount token is a volume — it would put a cloud-minted,
      # cloud-signed credential on the node disk of the one pod that must not
      # trust cloud-minted principals (decision 5). Nothing is lost: Workload
      # Identity does not read this token. GKE's metadata server identifies the
      # pod from its Kubernetes ServiceAccount out of band, so decision 8's
      # bucket credential still works with the token switched off.
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      # ScheduleAnyway, deliberately, and this is the opposite of the reflex.
      # DoNotSchedule is the "harder" setting and on Autopilot it is the one
      # that causes the outage it was meant to prevent: when only one node fits
      # the pod, a hard constraint leaves the second replica Pending forever and
      # the fleet runs at one replica — precisely the state decision 6 bought
      # the second replica to avoid. A soft constraint spreads across nodes
      # whenever the scheduler can and co-locates rather than refuses when it
      # cannot. Co-located replicas still survive a single-pod OOM and a
      # rollout; a Pending replica survives nothing.
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: datasphered
      serviceAccountName: {{.Name}}
      containers:
        - name: datasphered
          image: {{.Image}}
          args:
            - serve
            - --listen=:{{.DataPort}}
            - --status-listen=:{{.StatusPort}}
            - --unseal-listen=:{{.UnsealPort}}
            - --instance={{.Instance}}
            - --bucket={{.Bucket}}
            - --provider={{.Provider}}
{{- if .Project}}
            - --project={{.Project}}
{{- end}}
{{- if .Location}}
            - --location={{.Location}}
{{- end}}
          env:
            # A panic in the process that holds the derived bundle must not
            # print goroutine stacks — and, with core dumps disabled, must not
            # leave a copy of RAM on node disk either (ADR 0008 decision 1).
            - name: GOTRACEBACK
              value: none
            # The mTLS material arrives as environment values, not as a mounted
            # Secret, because a Secret volume is still a volume. The trade is
            # named rather than hidden: env values are visible to anyone who can
            # read the Pod spec or /proc/1/environ inside this container, which
            # for a transport leaf is the same exposure the Secret already has.
            - name: DATASPHERED_TLS_CA
              valueFrom:
                secretKeyRef:
                  name: {{.SecretName}}
                  key: ca.crt
            - name: DATASPHERED_TLS_CERT
              valueFrom:
                secretKeyRef:
                  name: {{.SecretName}}
                  key: server.crt
            - name: DATASPHERED_TLS_KEY
              valueFrom:
                secretKeyRef:
                  name: {{.SecretName}}
                  key: server.key
          ports:
            - name: data
              containerPort: {{.DataPort}}
            - name: status
              containerPort: {{.StatusPort}}
            - name: unseal
              containerPort: {{.UnsealPort}}
          # Readiness means unsealed: /readyz answers 503 for as long as the
          # keyholder holds no key material, which is what keeps app traffic off
          # a replica that could only answer ErrStorageSealed.
          readinessProbe:
            httpGet:
              path: /readyz
              port: status
            periodSeconds: 5
            timeoutSeconds: 2
            failureThreshold: 3
          # Liveness is deliberately a DIFFERENT endpoint from readiness, and
          # /livez must never fail merely because the keyholder is sealed. Point
          # this at /readyz and a sealed replica is killed, restarted, sealed
          # again, and killed again — a crash loop whose only cure is the
          # operator, during exactly the window the operator is absent. Sealed
          # is a correct state, not a fault; only a wedged process is a fault.
          livenessProbe:
            httpGet:
              path: /livez
              port: status
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 2
            failureThreshold: 3
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
      # No volumes. Not an emptyDir (that is node disk), not a Secret volume,
      # not a projected token. ADR 0008 decision 1, stated as an absence
      # because an absence is what it is — see TestRenderHasNoVolumes.
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: datasphered
    app.kubernetes.io/managed-by: farcast
spec:
  # Voluntary disruptions — node drains for auto-repair and auto-upgrade,
  # eviction under bin-packing — are the routine events that would otherwise
  # seal the instance. minAvailable: 1 makes the drain wait rather than take the
  # last loaded replica. It does not survive a full pool walk or a zonal loss,
  # and ADR 0008 decision 6 records both halves of that sentence.
  minAvailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: datasphered
---
apiVersion: v1
kind: Service
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: datasphered
    app.kubernetes.io/managed-by: farcast
# The application data path, and the ONE Service that gates on readiness. A
# sealed replica must never receive storage traffic: it holds no key material,
# so every call it accepted would be an ErrStorageSealed that a Ready sibling
# would have served.
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: datasphered
  ports:
    - name: data
      port: {{.DataPort}}
      targetPort: data
---
apiVersion: v1
kind: Service
metadata:
  name: {{.StatusService}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: datasphered
    app.kubernetes.io/managed-by: farcast
spec:
  type: ClusterIP
  # Load-bearing, and the reason this Service exists separately at all. When
  # every replica is sealed the data Service above has zero endpoints, so an SDK
  # call to it fails at dial with an opaque connection error. That is the exact
  # scenario ADR 0008 decision 7 was written for — the one where the application
  # most needs to be told "sealed" rather than "broken" — and without
  # publishNotReadyAddresses the contract every application inherits would fail
  # in precisely the case it was fixed for.
  publishNotReadyAddresses: true
  selector:
    app.kubernetes.io/name: datasphered
  ports:
    - name: status
      port: {{.StatusPort}}
      targetPort: status
---
apiVersion: v1
kind: Service
metadata:
  name: {{.UnsealService}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: datasphered
    app.kubernetes.io/managed-by: farcast
spec:
  type: ClusterIP
  # Headless: no virtual IP, no load balancing. It exists for DNS, so each
  # replica has a stable name the operator can address deterministically —
  # {{.Name}}-0.{{.UnsealService}}.{{.Namespace}}.svc.cluster.local — because
  # unsealing is per-replica and "whichever pod the Service picked" is not an
  # answer when both must end up loaded.
  clusterIP: None
  # Equally load-bearing: a sealed pod is never Ready, and sealed is exactly
  # when the unseal path has to reach it. Without this the endpoints are empty
  # at the only moment they matter and the fleet cannot be bootstrapped at all.
  publishNotReadyAddresses: true
  selector:
    app.kubernetes.io/name: datasphered
  ports:
    - name: unseal
      port: {{.UnsealPort}}
      targetPort: unseal
`))
