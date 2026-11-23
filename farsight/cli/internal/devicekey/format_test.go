package devicekey

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// containsBytes reports whether s carries b, or a 24-byte run from its middle,
// raw, as hex in either case, as standard base64, as Go's decimal list, or
// quoted.
func containsBytes(s string, b []byte) bool {
	if len(b) == 0 {
		return false
	}
	chunks := [][]byte{b}
	if len(b) > 48 {
		o := len(b) / 2 / 3 * 3 // aligned to 3, so its base64 is a run of b's
		chunks = append(chunks, b[o:o+24])
	}
	lower := strings.ToLower(s)
	for _, c := range chunks {
		q := strconv.Quote(string(c))
		if strings.Contains(s, string(c)) ||
			strings.Contains(lower, hex.EncodeToString(c)) ||
			strings.Contains(s, base64.StdEncoding.EncodeToString(c)) ||
			strings.Contains(s, decimalList(c)) ||
			strings.Contains(s, q[1:len(q)-1]) {
			return true
		}
	}
	return false
}

// decimalList is b as fmt prints a byte slice, without the brackets.
func decimalList(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = strconv.Itoa(int(c))
	}
	return strings.Join(parts, " ")
}

// containsID reports whether s carries id in any encoding containsBytes
// knows, or its hex in either case.
func containsID(s string, id RoleID) bool {
	if id.IsZero() {
		return false
	}
	return containsBytes(s, id.bytes()[:])
}

// plantedID is a fixed ID for the formatting tests.
func plantedID(t *testing.T) RoleID {
	t.Helper()
	id, err := ParseRoleID("c0ffee00deadbeef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// The formatting tests' holders.
type (
	exportedID            struct{ ID RoleID }
	unexportedID          struct{ id RoleID }
	unexportedIDPointer   struct{ id *RoleID }
	unexportedIDs         struct{ ids []RoleID }
	exportedIdentity      struct{ I Identity }
	unexportedIdentity    struct{ i Identity }
	unexportedIdentityPtr struct{ i *Identity }
	unexportedIdentities  struct{ ids []Identity }
)

// slogOutputs logs args with slog's text and JSON handlers.
func slogOutputs(args ...any) []string {
	var outs []string
	for _, h := range []func(*bytes.Buffer) slog.Handler{
		func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var buf bytes.Buffer
		slog.New(h(&buf)).Info("formatting", args...)
		outs = append(outs, buf.String())
	}
	return outs
}

// TestRoleIDNeverFormats: a planted ID's value never appears, under any fmt
// verb, as a value or a pointer, in a slice, in an exported or an unexported
// field, in JSON, or in slog; and a RoleID fmt can reach prints the fixed
// text exactly.
func TestRoleIDNeverFormats(t *testing.T) {
	id := plantedID(t)
	p := &id
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"}
	for _, verb := range append(verbs, "%p", "%t", "%08.3f", "%U", "%c", "%e") {
		for _, arg := range []any{id, p} {
			got := fmt.Sprintf(verb, arg)
			if containsID(got, id) {
				t.Errorf("%s of a %T prints the ID: %q", verb, arg, got)
			}
			if slices.Contains(verbs, verb) && got != roleIDText {
				t.Errorf("%s of a %T = %q, want %q", verb, arg, got, roleIDText)
			}
		}
		for _, arg := range []any{
			[]RoleID{id, id}, []*RoleID{p},
			exportedID{id}, &exportedID{id}, unexportedID{id}, &unexportedID{id},
			unexportedIDPointer{p}, &unexportedIDPointer{p}, unexportedIDs{[]RoleID{id}},
			map[string]RoleID{"k": id}, [1]RoleID{id},
		} {
			if got := fmt.Sprintf(verb, arg); containsID(got, id) {
				t.Errorf("%s of a %T prints the ID: %q", verb, arg, got)
			}
		}
	}
	for _, got := range []string{fmt.Sprint(id), fmt.Sprint(p), fmt.Sprintln(id), id.String(), id.GoString()} {
		if strings.TrimSpace(got) != roleIDText {
			t.Errorf("got %q, want %q", got, roleIDText)
		}
	}
	for i, v := range []any{id, p, exportedID{id}, unexportedID{id}, []RoleID{id}} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if containsID(string(b), id) {
			t.Errorf("json.Marshal of a %T prints the ID: %s", v, b)
		}
		if i == 0 && string(b) != "{}" {
			t.Errorf("json.Marshal(RoleID) = %s, want {}", b)
		}
	}
	for _, out := range slogOutputs("id", id, "ptr", p, "exported", exportedID{id}, "unexported", unexportedID{id}, "slice", []RoleID{id}) {
		if containsID(out, id) {
			t.Errorf("slog prints the ID: %s", out)
		}
		if !strings.Contains(out, roleIDText) {
			t.Errorf("slog did not use LogValue: %s", out)
		}
	}
	if id.LogValue().String() != roleIDText {
		t.Errorf("LogValue = %q", id.LogValue())
	}
}

// TestIdentityNeverFormats: an Identity's ID, leaf and anchor never appear,
// under any fmt verb, as a value or a pointer, in a slice, in an exported or
// an unexported field, in JSON, or in slog; and an Identity fmt can reach
// prints the fixed text exactly, naming its role only.
func TestIdentityNeverFormats(t *testing.T) {
	_, _, ids := enrolBoth(t)
	for _, id := range ids {
		want := id.Role().String() + " identity (not printed)"
		p := &id
		leaks := func(s string) string {
			switch {
			case containsID(s, id.ID()):
				return "the role ID"
			case containsBytes(s, id.LeafDER()):
				return "the leaf"
			case containsBytes(s, id.AnchorDER()):
				return "the anchor"
			}
			return ""
		}
		verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"}
		for _, verb := range append(verbs, "%p", "%t", "%08.3f", "%U", "%c", "%e") {
			for _, arg := range []any{id, p} {
				got := fmt.Sprintf(verb, arg)
				if what := leaks(got); what != "" {
					t.Errorf("%s of a %T prints %s", verb, arg, what)
				}
				if slices.Contains(verbs, verb) && got != want {
					t.Errorf("%s of a %T = %q, want %q", verb, arg, got, want)
				}
			}
			for _, arg := range []any{
				[]Identity{id}, []*Identity{p},
				exportedIdentity{id}, &exportedIdentity{id}, unexportedIdentity{id}, &unexportedIdentity{id},
				unexportedIdentityPtr{p}, &unexportedIdentityPtr{p}, unexportedIdentities{[]Identity{id}},
			} {
				if what := leaks(fmt.Sprintf(verb, arg)); what != "" {
					t.Errorf("%s of a %T prints %s", verb, arg, what)
				}
			}
		}
		for _, v := range []any{id, p, exportedIdentity{id}, unexportedIdentity{id}, []Identity{id}} {
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if what := leaks(string(b)); what != "" {
				t.Errorf("json.Marshal of a %T prints %s: %s", v, what, b)
			}
		}
		for _, out := range slogOutputs("identity", id, "ptr", p, "exported", exportedIdentity{id}, "unexported", unexportedIdentity{id}, "slice", []Identity{id}) {
			if what := leaks(out); what != "" {
				t.Errorf("slog prints %s: %s", what, out)
			}
			if !strings.Contains(out, want) {
				t.Errorf("slog did not use LogValue: %s", out)
			}
		}
	}
	var zero Identity
	if got := fmt.Sprintf("%v %d", zero, &zero); got != "identity (not printed) identity (not printed)" {
		t.Errorf("the zero Identity prints %q", got)
	}
}
