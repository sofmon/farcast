package kubetest

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// requestInfo is what the API server reads from a request's method and path
// before it authorizes it: a port, from memory and not fetched, of
// k8s.io/apiserver v0.37.2 pkg/endpoints/request/requestinfo.go
// (RequestInfoFactory.NewRequestInfo), without its watch and proxy prefixes.
type requestInfo struct {
	resourceRequest bool
	path            string
	verb            string
	group, version  string
	namespace       string
	resource        string
	subresource     string
	name            string // the object the path names; "" for a collection
	// authzName is the name authorization reads: name, or, for a list or a
	// watch, the name an exact metadata.name field selector requires, as
	// NewRequestInfo sets RequestInfo.Name for one. name stays "", so the
	// request is still served as the list it is.
	authzName string
}

// namespaceSubresources are the subresources of a Namespace object, which
// keep /namespaces/<n>/<sub> from reading as a resource in namespace <n>.
var namespaceSubresources = map[string]bool{"status": true, "finalize": true}

func parseRequestInfo(method, path string, q url.Values) requestInfo {
	ri := requestInfo{path: path}
	switch method {
	case http.MethodPost:
		ri.verb = "create"
	case http.MethodGet, http.MethodHead:
		ri.verb = "get"
	case http.MethodPut:
		ri.verb = "update"
	case http.MethodPatch:
		ri.verb = "patch"
	case http.MethodDelete:
		ri.verb = "delete"
	default:
		ri.verb = ""
	}

	parts := splitPath(path)
	if len(parts) < 3 || (parts[0] != "api" && parts[0] != "apis") {
		return ri
	}
	prefix := parts[0]
	parts = parts[1:]
	if prefix == "apis" {
		if len(parts) < 3 {
			return ri
		}
		ri.group = parts[0]
		parts = parts[1:]
	}
	ri.resourceRequest = true
	ri.version = parts[0]
	parts = parts[1:]

	if parts[0] == "namespaces" {
		if len(parts) > 1 {
			ri.namespace = parts[1]
			if len(parts) > 2 && !namespaceSubresources[parts[2]] {
				parts = parts[2:]
			}
		}
	}
	switch {
	case len(parts) >= 3:
		ri.subresource = parts[2]
		fallthrough
	case len(parts) >= 2:
		ri.name = parts[1]
		fallthrough
	case len(parts) >= 1:
		ri.resource = parts[0]
	}
	ri.authzName = ri.name
	if ri.name == "" && ri.verb == "get" {
		ri.verb = "list"
		if values, ok := q["watch"]; ok && len(values) > 0 && values[0] != "0" && !strings.EqualFold(values[0], "false") {
			ri.verb = "watch"
		}
		if name, ok := exactName(q.Get("fieldSelector")); ok && validPathSegmentName(name) {
			ri.authzName = name
		}
	}
	if ri.name == "" && ri.verb == "delete" {
		ri.verb = "deletecollection"
	}
	return ri
}

// exactName is the value of the first exact metadata.name term of a field
// selector, after the terms are sorted, as fields.Selector's
// RequiresExactMatch reads one (k8s.io/apimachinery v0.37.2 pkg/fields/selector.go:
// splitTerms, splitTerm, UnescapeValue, parseSelector). A selector that does
// not parse names nothing, as NewRequestInfo falls back to a plain list then.
func exactName(selector string) (string, bool) {
	var terms []string
	start, inSlash := 0, false
	for i, c := range selector {
		switch {
		case inSlash:
			inSlash = false
		case c == '\\':
			inSlash = true
		case c == ',':
			terms = append(terms, selector[start:i])
			start = i + 1
		}
	}
	if selector != "" {
		terms = append(terms, selector[start:])
	}
	sort.Strings(terms)
	name, found := "", false
	for _, term := range terms {
		if term == "" {
			continue
		}
		field, op, value, ok := splitSelectorTerm(term)
		if !ok {
			return "", false
		}
		v, ok := unescapeSelectorValue(value)
		if !ok {
			return "", false
		}
		if !found && field == "metadata.name" && op != "!=" {
			name, found = v, true
		}
	}
	return name, found
}

// splitSelectorTerm splits a term at its first operator: !=, ==, or =.
func splitSelectorTerm(term string) (field, op, value string, ok bool) {
	for i := range term {
		for _, op := range []string{"!=", "==", "="} {
			if strings.HasPrefix(term[i:], op) {
				return term[:i], op, term[i+len(op):], true
			}
		}
	}
	return "", "", "", false
}

// unescapeSelectorValue is UnescapeValue: a backslash before \, , or =
// stands for that character, and an unescaped , or =, or a backslash before
// anything else or at the end, is an error.
func unescapeSelectorValue(s string) (string, bool) {
	var b strings.Builder
	inSlash := false
	for _, c := range s {
		switch {
		case inSlash && (c == '\\' || c == ',' || c == '='):
			b.WriteRune(c)
			inSlash = false
		case inSlash:
			return "", false
		case c == '\\':
			inSlash = true
		case c == ',' || c == '=':
			return "", false
		default:
			b.WriteRune(c)
		}
	}
	return b.String(), !inSlash
}

// validPathSegmentName is apimachinery's IsValidPathSegmentName: not . or
// .., and no / or %.
func validPathSegmentName(name string) bool {
	return name != "." && name != ".." && !strings.ContainsAny(name, "/%")
}

// splitPath is the path's segments, as the API server splits them: r.URL.Path
// is already unescaped, once, by net/http, and is not unescaped again, so
// %252D on the wire is the name's own %2D.
func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

func (ri requestInfo) withVerb(verb string) requestInfo {
	ri.verb = verb
	return ri
}

// apiVersion is the request's group/version as a kind's apiVersion spells it.
func (ri requestInfo) apiVersion() string {
	if ri.group == "" {
		return ri.version
	}
	return ri.group + "/" + ri.version
}

// isSelfReview is the one request every authenticated user may make, as
// system:basic-user grants it: creating a SelfSubjectAccessReview.
func (ri requestInfo) isSelfReview() bool {
	return ri.resourceRequest && ri.verb == "create" && ri.group == "authorization.k8s.io" &&
		ri.resource == "selfsubjectaccessreviews" && ri.name == "" && ri.namespace == ""
}

// policyRule is rbac/v1's PolicyRule. Every tag is explicit: go-yaml
// lower-cases an untagged field's name.
type policyRule struct {
	APIGroups     []string `yaml:"apiGroups"`
	Resources     []string `yaml:"resources"`
	Verbs         []string `yaml:"verbs"`
	ResourceNames []string `yaml:"resourceNames"`
}

// rbacObject is the part of a Role, ClusterRole, RoleBinding or
// ClusterRoleBinding that authorization reads.
type rbacObject struct {
	Rules   []policyRule `yaml:"rules"`
	RoleRef struct {
		APIGroup string `yaml:"apiGroup"`
		Kind     string `yaml:"kind"`
		Name     string `yaml:"name"`
	} `yaml:"roleRef"`
	Subjects []struct {
		Kind     string `yaml:"kind"`
		APIGroup string `yaml:"apiGroup"`
		Name     string `yaml:"name"`
	} `yaml:"subjects"`
}

const rbacGroup = "rbac.authorization.k8s.io"

// authorizer is the rules one identity holds under WithRBAC.
type authorizer struct {
	cluster    []policyRule            // through ClusterRoleBindings
	namespaced map[string][]policyRule // through RoleBindings, by namespace
}

// newAuthorizer collects the rules stream grants to the user email. Bindings
// may come before the roles they name.
func newAuthorizer(email string, stream []byte) (*authorizer, error) {
	docs, err := kube.SplitStream(stream)
	if err != nil {
		return nil, fmt.Errorf("WithRBAC(%q): %w", email, err)
	}
	clusterRoles := map[string][]policyRule{}
	roles := map[string][]policyRule{} // by namespace/name
	type binding struct {
		namespace string
		obj       rbacObject
	}
	var clusterBindings, bindings []binding
	for _, d := range docs {
		if d.Kind.APIVersion != rbacGroup+"/v1" {
			continue
		}
		var o rbacObject
		if err := yaml.Unmarshal(d.Raw, &o); err != nil {
			return nil, fmt.Errorf("WithRBAC(%q): document %d (%s %q) does not decode: %w", email, d.Index, d.Kind.Kind, d.Name, err)
		}
		switch d.Kind.Kind {
		case "ClusterRole":
			clusterRoles[d.Name] = o.Rules
		case "Role":
			roles[d.Namespace+"/"+d.Name] = o.Rules
		case "ClusterRoleBinding":
			clusterBindings = append(clusterBindings, binding{obj: o})
		case "RoleBinding":
			bindings = append(bindings, binding{namespace: d.Namespace, obj: o})
		}
	}
	a := &authorizer{namespaced: map[string][]policyRule{}}
	for _, b := range clusterBindings {
		if bindsUser(b.obj, email) && b.obj.RoleRef.APIGroup == rbacGroup && b.obj.RoleRef.Kind == "ClusterRole" {
			a.cluster = append(a.cluster, clusterRoles[b.obj.RoleRef.Name]...)
		}
	}
	for _, b := range bindings {
		if !bindsUser(b.obj, email) || b.obj.RoleRef.APIGroup != rbacGroup {
			continue
		}
		switch b.obj.RoleRef.Kind {
		case "ClusterRole":
			a.namespaced[b.namespace] = append(a.namespaced[b.namespace], clusterRoles[b.obj.RoleRef.Name]...)
		case "Role":
			a.namespaced[b.namespace] = append(a.namespaced[b.namespace], roles[b.namespace+"/"+b.obj.RoleRef.Name]...)
		}
	}
	return a, nil
}

// bindsUser reports whether a binding names email as a User subject.
func bindsUser(o rbacObject, email string) bool {
	for _, s := range o.Subjects {
		if s.Kind == "User" && s.Name == email && (s.APIGroup == "" || s.APIGroup == rbacGroup) {
			return true
		}
	}
	return false
}

// allows reports whether any rule the identity holds allows the request: a
// cluster-wide rule for any request, a RoleBinding's rule for a request in
// its namespace only. A request that names no namespace (a cluster-scoped
// object, or a list across every namespace) is therefore granted only
// cluster-wide. Non-resource paths are granted nothing.
func (a *authorizer) allows(ri requestInfo) bool {
	if !ri.resourceRequest {
		return false
	}
	for _, r := range a.cluster {
		if ruleAllows(r, ri) {
			return true
		}
	}
	if ri.namespace != "" {
		for _, r := range a.namespaced[ri.namespace] {
			if ruleAllows(r, ri) {
				return true
			}
		}
	}
	return false
}

// ruleAllows is a port, from memory and not fetched, of kubernetes v1.37.2
// plugin/pkg/auth/authorizer/rbac/rbac.go (RuleAllows) and
// pkg/apis/rbac/v1/evaluation_helpers.go (VerbMatches, APIGroupMatches,
// ResourceMatches, ResourceNameMatches): the verb, the group, the resource
// ("pods/log" for a subresource, "*" and "*/<sub>" as wildcards) and, when the
// rule names any, the object's name must all match. A rule with resourceNames
// never matches a request that names no object: a list or a watch names one
// only through an exact metadata.name field selector (authzName).
func ruleAllows(r policyRule, ri requestInfo) bool {
	combined := ri.resource
	if ri.subresource != "" {
		combined += "/" + ri.subresource
	}
	return matchesAny(r.Verbs, ri.verb) &&
		matchesAny(r.APIGroups, ri.group) &&
		resourceMatches(r.Resources, combined, ri.subresource) &&
		resourceNameMatches(r.ResourceNames, ri.authzName)
}

func matchesAny(list []string, want string) bool {
	for _, v := range list {
		if v == "*" || v == want {
			return true
		}
	}
	return false
}

func resourceMatches(rules []string, combined, subresource string) bool {
	for _, r := range rules {
		if r == "*" || r == combined {
			return true
		}
		if subresource != "" && r == "*/"+subresource {
			return true
		}
	}
	return false
}

func resourceNameMatches(names []string, name string) bool {
	if len(names) == 0 {
		return true
	}
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}
