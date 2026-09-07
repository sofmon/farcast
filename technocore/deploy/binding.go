package deploy

import (
	"bytes"
	"fmt"
	"text/template"
)

// RenderNamespaceBinding produces the RoleBinding that lets the kernel meter
// one namespace.
//
// It lives here, in TechnoCore's own package, rather than in the translator
// that creates application namespaces. TechnoCore owns its RBAC: a translator
// that wrote its own version of this binding would be a second copy of the
// kernel's permission model, free to drift from the ClusterRole it references
// — and the drift would surface as a kernel that cannot list pods in a
// namespace it was told to meter.
//
// Applying it is what makes an application visible to the cost meter at all.
// Without it the kernel is told to meter a namespace it has no permission to
// list, which is a loud failure — and forgetting the binding *and* the
// namespace list together is the quiet one: an application that runs, bills,
// and is counted nowhere.
func RenderNamespaceBinding(namespace, name, kernelNamespace string) ([]byte, error) {
	if namespace == "" {
		return nil, fmt.Errorf("deploy: a namespace binding needs a namespace")
	}
	if name == "" {
		name = DefaultName
	}
	if kernelNamespace == "" {
		kernelNamespace = DefaultNamespace
	}
	var buf bytes.Buffer
	if err := bindingTemplate.Execute(&buf, struct{ Namespace, Name, KernelNamespace string }{
		Namespace: namespace, Name: name, KernelNamespace: kernelNamespace,
	}); err != nil {
		return nil, fmt.Errorf("deploy: render the namespace binding: %w", err)
	}
	return buf.Bytes(), nil
}

// bindingTemplate grants the kernel's ClusterRole inside one namespace. A
// ClusterRole is a rule set, not a grant: this is what keeps the kernel's
// reach to the namespaces FarCast owns rather than the whole cluster.
var bindingTemplate = template.Must(template.New("binding").Parse(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app.kubernetes.io/name: technocore
    app.kubernetes.io/managed-by: farcast
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{.Name}}
subjects:
  - kind: ServiceAccount
    name: {{.Name}}
    namespace: {{.KernelNamespace}}
`))
