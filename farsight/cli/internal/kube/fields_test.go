package kube

import (
	"encoding/json"
	"testing"
)

// TestUnionFields is §6.3's union: membership is kept, children are merged
// recursively, and the result is written with sorted keys and ".":{} wherever
// a member also has children.
func TestUnionFields(t *testing.T) {
	cases := []struct{ name, a, b, want string }{
		{"a member and a child", `{}`, `{"f:x":{}}`, `{".":{},"f:x":{}}`},
		{"the same, the other way round", `{"f:x":{}}`, `{}`, `{".":{},"f:x":{}}`},
		{"a nested member and a nested child", `{"f:a":{}}`, `{"f:a":{"f:b":{}}}`, `{"f:a":{".":{},"f:b":{}}}`},
		{"disjoint children", `{"f:a":{"f:b":{}}}`, `{"f:a":{"f:c":{}}}`, `{"f:a":{"f:b":{},"f:c":{}}}`},
		{"a member's mark survives", `{"f:a":{".":{},"f:b":{}}}`, `{"f:a":{"f:c":{}}}`, `{"f:a":{".":{},"f:b":{},"f:c":{}}}`},
		{"keys are sorted", `{"f:z":{},"v:\"b\"":{}}`, `{"f:a":{},"i:0":{},"k:{\"name\":\"api\"}":{}}`,
			`{"f:a":{},"f:z":{},"i:0":{},"k:{\"name\":\"api\"}":{},"v:\"b\"":{}}`},
		{"identical sets", `{"f:metadata":{"f:labels":{"f:app":{}}}}`, `{"f:metadata":{"f:labels":{"f:app":{}}}}`,
			`{"f:metadata":{"f:labels":{"f:app":{}}}}`},
		{"a lone mark is a member", `{".":{}}`, `{}`, `{}`},
		{"keys are written as the server wrote them", `{"v:\"<a&b>\"":{}}`, `{}`, `{".":{},"v:\"<a&b>\"":{}}`},
		{"a container list", `{"f:spec":{"f:containers":{"k:{\"name\":\"api\"}":{".":{},"f:image":{}}}}}`,
			`{"f:spec":{"f:containers":{"k:{\"name\":\"api\"}":{"f:args":{}},"k:{\"name\":\"shrike\"}":{".":{},"f:name":{}}}}}`,
			`{"f:spec":{"f:containers":{"k:{\"name\":\"api\"}":{".":{},"f:args":{},"f:image":{}},"k:{\"name\":\"shrike\"}":{".":{},"f:name":{}}}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UnionFields(json.RawMessage(tc.a), json.RawMessage(tc.b))
			if err != nil {
				t.Fatalf("UnionFields: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("UnionFields(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.want)
			}
		})
	}

	for _, bad := range []string{``, `  `, `null`, `[]`, `"x"`, `{"f:a":1}`, `{"x:a":{}}`, `{".":{"f:a":{}}}`, `{"f:a":{".":[]}}`, `{`} {
		if got, err := UnionFields(json.RawMessage(bad), json.RawMessage(`{}`)); err == nil {
			t.Errorf("UnionFields(%q, {}) = %s, want an error", bad, got)
		}
		if got, err := UnionFields(json.RawMessage(`{}`), json.RawMessage(bad)); err == nil {
			t.Errorf("UnionFields({}, %q) = %s, want an error", bad, got)
		}
	}
}

// TestRemoveField is §6.3's removal: the leaf goes, then every parent left
// empty that was not a member; a path the set does not hold changes nothing,
// byte for byte.
func TestRemoveField(t *testing.T) {
	ann := []string{"f:metadata", "f:annotations", "f:kubectl.kubernetes.io/last-applied-configuration"}
	cases := []struct {
		name, in string
		path     []string
		want     string
	}{
		{"the parents collapse", `{"f:metadata":{"f:annotations":{"f:kubectl.kubernetes.io/last-applied-configuration":{}}}}`, ann, `{}`},
		{"a sibling keeps its parent",
			`{"f:metadata":{"f:annotations":{"f:a":{},"f:kubectl.kubernetes.io/last-applied-configuration":{}}}}`, ann,
			`{"f:metadata":{"f:annotations":{"f:a":{}}}}`},
		{"a member parent stays, as a leaf",
			`{"f:metadata":{"f:annotations":{".":{},"f:kubectl.kubernetes.io/last-applied-configuration":{}}}}`, ann,
			`{"f:metadata":{"f:annotations":{}}}`},
		{"a parent's siblings stay",
			`{"f:metadata":{"f:annotations":{"f:kubectl.kubernetes.io/last-applied-configuration":{}},"f:labels":{"f:app":{}}},"f:spec":{"f:replicas":{}}}`, ann,
			`{"f:metadata":{"f:labels":{"f:app":{}}},"f:spec":{"f:replicas":{}}}`},
		{"an absent leaf changes nothing", `{"f:metadata": {"f:annotations": {"f:a": {}}}}`, ann, `{"f:metadata": {"f:annotations": {"f:a": {}}}}`},
		{"an absent parent changes nothing", `{"f:spec" : {}}`, ann, `{"f:spec" : {}}`},
		{"a path through a leaf changes nothing", `{"f:metadata":{}}`, ann, `{"f:metadata":{}}`},
		{"a one-element path", `{"f:a":{},"f:b":{}}`, []string{"f:a"}, `{"f:b":{}}`},
		{"the leaf goes with its children", `{"f:a":{".":{},"f:b":{}},"f:c":{}}`, []string{"f:a"}, `{"f:c":{}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RemoveField(json.RawMessage(tc.in), tc.path...)
			if err != nil {
				t.Fatalf("RemoveField: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("RemoveField(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
	if _, err := RemoveField(json.RawMessage(`{}`)); err == nil {
		t.Error("RemoveField with no path succeeded")
	}
	if _, err := RemoveField(json.RawMessage(`{"f:a":[]}`), "f:a"); err == nil {
		t.Error("RemoveField on a set that does not parse succeeded")
	}
}
