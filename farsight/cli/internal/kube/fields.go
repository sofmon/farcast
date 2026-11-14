package kube

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

// FieldsV1 is the API server's encoding of a set of field paths as a trie
// (§6.3). The rules this file follows, inferred from the format and verified
// against a real API server by §10.6's tests:
//   - a node is a JSON object;
//   - an empty object {} means the path is a member of the set, with no
//     children;
//   - a non-empty object has children keyed f:, k:, v: or i:, plus an optional
//     ".":{} that marks the path itself as a member.
//
// The rule is applied at every node, the root included, as §6.3 pins it.

// fieldNode is one node of a FieldsV1 trie.
type fieldNode struct {
	member   bool
	children map[string]*fieldNode
}

var (
	errFieldsEmpty     = errors.New("kube: a fieldsV1 value is empty")
	errFieldsNotObject = errors.New("kube: a fieldsV1 node is not a JSON object")
	errFieldsBadSelf   = errors.New(`kube: a fieldsV1 "." is not {}`)
	errFieldsBadKey    = errors.New("kube: a fieldsV1 key is not a path element (f:, k:, v: or i:)")
	errFieldsNoPath    = errors.New("kube: RemoveField needs a path")
)

// parseFields reads one FieldsV1 value. Its errors name no key: a k: or v:
// key carries a value from the object.
func parseFields(raw json.RawMessage) (*fieldNode, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errFieldsEmpty
	}
	return parseFieldNode(raw)
}

func parseFieldNode(raw json.RawMessage) (*fieldNode, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, errFieldsNotObject
	}
	n := &fieldNode{}
	if len(obj) == 0 {
		n.member = true
		return n, nil
	}
	for k, v := range obj {
		if k == "." {
			var self map[string]json.RawMessage
			if err := json.Unmarshal(v, &self); err != nil || self == nil || len(self) != 0 {
				return nil, errFieldsBadSelf
			}
			n.member = true
			continue
		}
		if !isPathElement(k) {
			return nil, errFieldsBadKey
		}
		c, err := parseFieldNode(v)
		if err != nil {
			return nil, err
		}
		if n.children == nil {
			n.children = map[string]*fieldNode{}
		}
		n.children[k] = c
	}
	return n, nil
}

func isPathElement(k string) bool {
	return strings.HasPrefix(k, "f:") || strings.HasPrefix(k, "k:") ||
		strings.HasPrefix(k, "v:") || strings.HasPrefix(k, "i:")
}

// encode writes n as {} when it has no children, and otherwise as its
// children plus ".":{} when it is a member, keys in sorted order ("." sorts
// before every path element).
func (n *fieldNode) encode(buf *bytes.Buffer) {
	if len(n.children) == 0 {
		buf.WriteString("{}")
		return
	}
	buf.WriteByte('{')
	first := true
	if n.member {
		buf.WriteString(`".":{}`)
		first = false
	}
	keys := make([]string, 0, len(n.children))
	for k := range n.children {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if !first {
			buf.WriteByte(',')
		}
		first = false
		writeJSONString(buf, k)
		buf.WriteByte(':')
		n.children[k].encode(buf)
	}
	buf.WriteByte('}')
}

// writeJSONString writes s as a JSON string without HTML escaping, so a key
// is written as the server wrote it.
func writeJSONString(buf *bytes.Buffer, s string) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	buf.Write(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
}

func (n *fieldNode) bytes() json.RawMessage {
	var buf bytes.Buffer
	n.encode(&buf)
	return buf.Bytes()
}

func unionNodes(a, b *fieldNode) *fieldNode {
	u := &fieldNode{member: a.member || b.member}
	for _, side := range [...]*fieldNode{a, b} {
		for k, c := range side.children {
			if u.children == nil {
				u.children = map[string]*fieldNode{}
			}
			if prev, ok := u.children[k]; ok {
				u.children[k] = unionNodes(prev, c)
			} else {
				u.children[k] = unionNodes(c, &fieldNode{})
			}
		}
	}
	return u
}

// UnionFields is the union of two FieldsV1 sets (§6.3): a node is a member
// when either input's is (an empty {} counts as one), and its children are
// the recursive union of both sides' children. The result is written in the
// canonical form encode describes.
func UnionFields(a, b json.RawMessage) (json.RawMessage, error) {
	na, err := parseFields(a)
	if err != nil {
		return nil, err
	}
	nb, err := parseFields(b)
	if err != nil {
		return nil, err
	}
	return unionNodes(na, nb).bytes(), nil
}

// RemoveField deletes one path from a FieldsV1 set (§6.3): the leaf key goes,
// and then, walking back up, every parent that is now empty and was not a
// member (it had no ".") goes too. A path the set does not hold leaves f as
// it was, byte for byte; otherwise the result is re-encoded canonically.
func RemoveField(f json.RawMessage, path ...string) (json.RawMessage, error) {
	if len(path) == 0 {
		return nil, errFieldsNoPath
	}
	root, err := parseFields(f)
	if err != nil {
		return nil, err
	}
	// stack[i] is the node at path[:i].
	stack := []*fieldNode{root}
	for _, p := range path[:len(path)-1] {
		next, ok := stack[len(stack)-1].children[p]
		if !ok {
			return f, nil
		}
		stack = append(stack, next)
	}
	parent := stack[len(stack)-1]
	if _, ok := parent.children[path[len(path)-1]]; !ok {
		return f, nil
	}
	delete(parent.children, path[len(path)-1])
	for i := len(stack) - 1; i >= 1; i-- {
		n := stack[i]
		if len(n.children) > 0 || n.member {
			break
		}
		delete(stack[i-1].children, path[i-1])
	}
	return root.bytes(), nil
}

// ownsPath reports whether a FieldsV1 set holds path as a member. An absent
// set owns nothing.
func ownsPath(f json.RawMessage, path []string) (bool, error) {
	if len(bytes.TrimSpace(f)) == 0 {
		return false, nil
	}
	n, err := parseFields(f)
	if err != nil {
		return false, err
	}
	for _, p := range path {
		next, ok := n.children[p]
		if !ok {
			return false, nil
		}
		n = next
	}
	return n.member, nil
}
