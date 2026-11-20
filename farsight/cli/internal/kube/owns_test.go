package kube

import (
	"encoding/json"
	"slices"
	"testing"
)

// owns is whether an entry's fields hold path, false when they do not read.
// It walks the fieldsV1 trie down path's keys, each node a JSON object, and
// the node it ends at holds the path when it is {} or carries ".". The
// real-API suite reads managed fields through it (realapi_test.go), and that
// suite never runs in ./check.sh, so TestOwnsWalksTheFieldsV1Trie pins it here
// (ADR 0023 M2.9a, design §37, A37-9).
func owns(e ManagedFieldsEntry, path ...string) bool {
	node := e.FieldsV1
	for _, key := range path {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(node, &m); err != nil || m == nil {
			return false
		}
		next, ok := m[key]
		if !ok {
			return false
		}
		node = next
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(node, &m); err != nil || m == nil {
		return false
	}
	_, member := m["."]
	return len(m) == 0 || member
}

// The sets below are drawn from the real-API suite's own documents by the
// fieldsV1 format's rules (§6.3), and none was read from a server.

// fatlineFields is farcast/Apply's set after a forced apply of the suite's
// fatlineV1: keyed lists (k:) for its containers, volumes and mounts, each
// item carrying ".", an atomic list for args and an atomic struct for the
// selector.
const fatlineFields = `{"f:metadata":{"f:labels":{"f:app.kubernetes.io/managed-by":{},"f:app.kubernetes.io/name":{},"f:realapi.farcast.sofmon.com/seed":{}}},
"f:spec":{"f:replicas":{},"f:selector":{},"f:template":{
 "f:metadata":{"f:labels":{"f:app.kubernetes.io/managed-by":{},"f:app.kubernetes.io/name":{}}},
 "f:spec":{"f:automountServiceAccountToken":{},
  "f:containers":{
   "k:{\"name\":\"fatline\"}":{".":{},"f:args":{},"f:image":{},"f:name":{},"f:resources":{"f:requests":{"f:cpu":{},"f:memory":{}}},
    "f:volumeMounts":{"k:{\"mountPath\":\"/etc/fatline/policy\"}":{".":{},"f:mountPath":{},"f:name":{},"f:readOnly":{}},"k:{\"mountPath\":\"/run/fatline\"}":{".":{},"f:mountPath":{},"f:name":{}}}},
   "k:{\"name\":\"shrike\"}":{".":{},"f:args":{},"f:image":{},"f:name":{},"f:resources":{"f:requests":{"f:cpu":{},"f:memory":{}}},
    "f:volumeMounts":{"k:{\"mountPath\":\"/run/fatline\"}":{".":{},"f:mountPath":{},"f:name":{}}}}},
  "f:volumes":{"k:{\"name\":\"policy\"}":{".":{},"f:configMap":{"f:name":{},"f:optional":{}},"f:name":{}},"k:{\"name\":\"shrike-wire\"}":{".":{},"f:emptyDir":{},"f:name":{}}}}}}}`

// scaledAppFields is farcast/Apply's set for the suite's appV2 after the
// kernel's Scale to 0, which on v1.36.2 left no entry owning spec.replicas
// (A31-5): its apply's set without f:replicas.
const scaledAppFields = `{"f:metadata":{"f:labels":{"f:app.kubernetes.io/managed-by":{},"f:app.kubernetes.io/name":{},"f:realapi.farcast.sofmon.com/seed":{}}},
"f:spec":{"f:selector":{},"f:template":{
 "f:metadata":{"f:labels":{"f:app.kubernetes.io/managed-by":{},"f:app.kubernetes.io/name":{}}},
 "f:spec":{"f:containers":{"k:{\"name\":\"api\"}":{".":{},"f:env":{"k:{\"name\":\"FARCAST_APP_NAME\"}":{".":{},"f:name":{},"f:value":{}}},"f:image":{},"f:name":{},"f:resources":{"f:requests":{"f:cpu":{},"f:memory":{}}}}}}}}}`

// TestOwnsWalksTheFieldsV1Trie pins owns on the shapes the real-API suite
// meets: a leaf {}, a node carrying ".", nested and keyed (k:) paths, a path
// that is absent, and a prefix of owned paths that is not itself owned. The
// suite's documents hold no set of scalars, so no v: key is drawn here.
func TestOwnsWalksTheFieldsV1Trie(t *testing.T) {
	containers := []string{"f:spec", "f:template", "f:spec", "f:containers"}
	under := func(keys ...string) []string { return append(slices.Clone(containers), keys...) }
	for _, tc := range []struct {
		name, fields string
		path         []string
		want         bool
	}{
		{"an empty-object leaf is owned", fatlineFields, []string{"f:spec", "f:replicas"}, true},
		{"an atomic struct is a leaf, and owned", fatlineFields, []string{"f:spec", "f:selector"}, true},
		{"a keyed list item carrying . is owned", fatlineFields, under(`k:{"name":"shrike"}`), true},
		{"a leaf under a keyed list item is owned", fatlineFields, under(`k:{"name":"shrike"}`, "f:args"), true},
		{"a nested keyed path is owned", fatlineFields, under(`k:{"name":"fatline"}`, "f:volumeMounts", `k:{"mountPath":"/etc/fatline/policy"}`, "f:readOnly"), true},
		{"a keyed list itself, a prefix of owned paths, is not owned", fatlineFields, under(), false},
		{"spec, a prefix of owned paths, is not owned", fatlineFields, []string{"f:spec"}, false},
		{"an absent field is not owned", fatlineFields, []string{"f:spec", "f:paused"}, false},
		{"an absent keyed item is not owned", fatlineFields, under(`k:{"name":"api"}`), false},
		{"a path below a leaf is not owned", fatlineFields, []string{"f:spec", "f:selector", "f:matchLabels"}, false},
		{"replicas the Scale to 0 took is not owned", scaledAppFields, []string{"f:spec", "f:replicas"}, false},
		{"a keyed item of the scaled set is still owned", scaledAppFields, under(`k:{"name":"api"}`), true},
		{"realapi-other's merge PATCH owns replicas", `{"f:spec":{"f:replicas":{}}}`, []string{"f:spec", "f:replicas"}, true},
		{"the kernel's ConfigMap POST owns its data map, which carries .", `{"f:data":{".":{},"f:ledger":{}}}`, []string{"f:data"}, true},
		{"the kernel's ConfigMap POST owns its data key", `{"f:data":{".":{},"f:ledger":{}}}`, []string{"f:data", "f:ledger"}, true},
		{"kubetest's empty set owns no field", `{}`, []string{"f:spec", "f:replicas"}, false},
		{"an entry with no fieldsV1 owns nothing", "", []string{"f:spec", "f:replicas"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := ManagedFieldsEntry{Manager: FieldManager, Operation: operationApply, FieldsType: "FieldsV1"}
			if tc.fields != "" {
				if !json.Valid([]byte(tc.fields)) {
					t.Fatal("the case's fieldsV1 is not JSON")
				}
				e.FieldsV1 = json.RawMessage(tc.fields)
			}
			if got := owns(e, tc.path...); got != tc.want {
				t.Errorf("owns(%v) = %t, want %t", tc.path, got, tc.want)
			}
		})
	}
}
