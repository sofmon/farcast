package cli

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

// The reader's Kubernetes RBAC (ADR 0023 M2.3, design §7.2, P3 decided): two
// ClusterRoles, one bound cluster-wide and holding only namespaces list, the
// other a rule set bound per namespace, in farcast-system and in every
// namespace the kernel meters. The reader is therefore never bound in a kube-
// namespace, kube-system among them: validNamespace refuses those, for the
// reader's bindings as for the kernel's. GKE's other managed namespaces
// (gke-managed-system, gmp-system and the like) are not refused, so the reader
// is bound in one exactly when the operator meters it, as the kernel is. A
// binding outlives 'kernel meter --remove', which deletes nothing.

// readerScopeMetered is Reader.Scope once 'reader grant' has verified the
// reader read-only: the scope its consent named, farcast-system and every
// namespace the kernel meters, now and later. Only with it do 'kernel meter',
// 'kernel deploy' and 'run' bind the reader in a namespace they meter.
const readerScopeMetered = "metered"

// The names of the reader's RBAC objects. kube's kind table allows a
// ClusterRoleBinding by the one name readerNamespacesRole only.
const (
	readerRole           = "farcast-reader"
	readerNamespacesRole = "farcast-reader-namespaces"
)

// readerConfigMaps are the ConfigMaps the reader may get, by name: exactly the
// names the read commands and the plan builders pass, taken from the same
// constants those call sites use, so the two cannot drift apart
// (TestReaderRoleNamesTheConfigMapsReadsUse). technocore-confirmed is not
// among them: only 'kernel confirm' writes it, and nothing reads it.
var readerConfigMaps = []string{
	kernel.DefaultNamespacesName,  // world.go
	kernel.DefaultCheckpointName,  // costs.go, world.go
	kernel.DefaultProfilesName,    // usage.go
	fldeploy.PolicyConfigMap,      // runpolicy.go
	dsdeploy.PinConfigMapName(""), // storagepin.go
}

// readerSubjectShape is every email a reader's RBAC may name: the derived
// account, farcast-reader- and 8 hex characters, at a project's
// iam.gserviceaccount.com (Google mode) or at a test name under .invalid
// (loopback mode, the domain derivedReader accepts). It holds only characters
// a plain YAML scalar keeps as they are, so the email can never become more
// than one scalar in the stream.
var readerSubjectShape = regexp.MustCompile(
	`^farcast-reader-[0-9a-f]{8}@(?:[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com|` + loopbackReaderDomain + `)$`)

// checkReaderSubject refuses an email the reader's RBAC may not name.
func checkReaderSubject(email string) error {
	if !readerSubjectShape.MatchString(email) {
		return fmt.Errorf("the reader %q is not an account farcast derives for a reader (farcast-reader- and 8 hex characters, "+
			"at a project's iam.gserviceaccount.com or at a test name under .invalid); no RBAC was rendered for it", email)
	}
	return nil
}

// readerBoundNamespaces is the namespaces the reader's RoleBindings go into:
// farcast-system first, then each of namespaces in its order, once each. Every
// one must be a DNS label outside kube- (validNamespace, as 'kernel meter'
// checks what it meters), so it stays one YAML scalar and never names a kube-
// namespace.
func readerBoundNamespaces(namespaces []string) ([]string, error) {
	out := []string{tcdeploy.DefaultNamespace}
	for _, ns := range namespaces {
		if err := validNamespace(ns); err != nil {
			return nil, fmt.Errorf("namespace %q: %v; no RBAC was rendered for the reader", ns, err)
		}
		if !slices.Contains(out, ns) {
			out = append(out, ns)
		}
	}
	return out, nil
}

// renderReaderRBAC is the whole of the reader's RBAC, as 'reader grant'
// applies it: the cluster-wide namespaces list (a ClusterRole and its
// ClusterRoleBinding), the per-namespace rule set (a ClusterRole never bound
// cluster-wide), and one RoleBinding of that rule set in farcast-system and in
// each of namespaces.
func renderReaderRBAC(email string, namespaces []string) ([]byte, error) {
	if err := checkReaderSubject(email); err != nil {
		return nil, err
	}
	bound, err := readerBoundNamespaces(namespaces)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(readerNamespacesRoleDoc)
	buf.WriteString("---\n")
	buf.WriteString(strings.NewReplacer("{{EMAIL}}", email).Replace(readerNamespacesBindingTemplate))
	buf.WriteString("---\n")
	buf.WriteString(strings.NewReplacer("{{CONFIGMAPS}}", strings.Join(readerConfigMaps, ", ")).Replace(readerRoleTemplate))
	for _, ns := range bound {
		b, err := renderReaderBinding(email, ns)
		if err != nil {
			return nil, err
		}
		buf.WriteString("---\n")
		buf.Write(b)
	}
	return buf.Bytes(), nil
}

// renderReaderBinding is one RoleBinding of the reader's rule set in one
// namespace: what 'kernel meter', 'kernel deploy' and 'run' add beside the
// kernel's own binding once 'reader grant' has recorded the metered scope.
func renderReaderBinding(email, namespace string) ([]byte, error) {
	if err := checkReaderSubject(email); err != nil {
		return nil, err
	}
	if err := validNamespace(namespace); err != nil {
		return nil, fmt.Errorf("namespace %q: %v; no RBAC was rendered for the reader", namespace, err)
	}
	return []byte(strings.NewReplacer("{{EMAIL}}", email, "{{NAMESPACE}}", namespace).Replace(readerBindingTemplate)), nil
}

// The four document shapes of design §7.2. Every substituted value is checked
// first: the email by checkReaderSubject, a namespace by validNamespace, and
// the ConfigMap names are constants.
const (
	readerNamespacesRoleDoc = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: farcast-reader-namespaces
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: farcast-reader
rules:
- apiGroups: [""]
  resources: [namespaces]
  verbs: [list]
`
	readerNamespacesBindingTemplate = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: farcast-reader-namespaces
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: farcast-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: farcast-reader-namespaces
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: {{EMAIL}}
`
	readerRoleTemplate = `# A rule set, never bound cluster-wide: each RoleBinding below grants it in one namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: farcast-reader
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: farcast-reader
rules:
- apiGroups: [apps]
  resources: [deployments, statefulsets]
  verbs: [get, list]
- apiGroups: [""]
  resources: [pods]
  verbs: [list]
- apiGroups: [""]
  resources: [pods/log]
  verbs: [get]
- apiGroups: [batch]
  resources: [jobs]
  verbs: [get]
- apiGroups: [""]
  resources: [configmaps]
  resourceNames: [{{CONFIGMAPS}}]
  verbs: [get]
`
	readerBindingTemplate = `# One per namespace: farcast-system, and every metered namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: farcast-reader
  namespace: {{NAMESPACE}}
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: farcast-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: farcast-reader
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: {{EMAIL}}
`
)

// msgReaderBinding is how a command's result names each reader binding it
// adds.
const msgReaderBinding = "the reader %s may now read %s"

// readerSubject is the email the reader's RBAC binds for an instance: the
// recorded one, once checkedReader accepts the record and the email is the
// one farcast derives for the instance's mode, openCluster's own check (in
// Google mode it is then byte-equal to readerEmail(name, project); in loopback
// mode it is readerName(name) at a test name under .invalid). The renderers
// check its shape again.
func readerSubject(dir config.Dir, meta *config.InstanceMetadata) (string, error) {
	if _, _, _, err := checkedReader(meta); err != nil {
		return "", err
	}
	if meta.Reader == nil {
		return "", refuse(errCredentialMissing, "instance %q has no reader identity; run 'farcast reader init %s'", meta.Name, meta.Name)
	}
	// "No RBAC was rendered for it" holds for 'reader grant' and for the
	// three commands that bind the reader later, which print this inside a
	// warning and then apply their own stream without it.
	if derived, ok := recordedReaderIsDerived(dir, meta); !ok {
		return "", refuse(errCredentialMissing, "instance %q records the reader %q, which is not the reader farcast derives for it (%s); no RBAC was rendered for it",
			meta.Name, meta.Reader.Email, derived)
	}
	return meta.Reader.Email, checkReaderSubject(meta.Reader.Email)
}

// readerIAMRole is the one IAM role the Cloud Shell script grants the reader,
// which 'reader grant' asks consent to rely on and its plan binds.
const readerIAMRole = "roles/container.clusterViewer"

// readerResources is what the reader's rule set grants per namespace, in
// readerRoleTemplate's rule order, the ConfigMaps aside (readerConfigMaps
// names those): the reader fact's resources (design §9.4, A23-33;
// TestReaderResourcesFollowTheRoleRuleOrder).
var readerResources = []string{"deployments", "statefulsets", "pods", "pods/log", "jobs"}

// meteredReaderNote is the reader email a command that starts metering a
// namespace binds there beside the kernel (design §7.2, "Where each part is
// applied"): only when 'reader grant' recorded the metered scope, the consent
// to "every namespace the kernel meters, now and later". Otherwise, and when
// the record cannot be rendered from, it is "" and no reader binding is
// added. In the second case it also returns warning, the line its caller
// prints (or, in a plan, carries as a notice; A23-26), since 'reader grant'
// would otherwise lead the operator to expect a binding.
func meteredReaderNote(env *Env, name string, meta *config.InstanceMetadata) (email, warning string) {
	if meta.Reader == nil || meta.Reader.Scope != readerScopeMetered {
		return "", ""
	}
	email, err := readerSubject(env.ConfigDir, meta)
	if err != nil {
		return "", fmt.Sprintf("Warning: no reader binding is added: %v. 'farcast reader grant %s' binds the reader in every metered namespace once the record is fixed.", err, name)
	}
	return email, ""
}
