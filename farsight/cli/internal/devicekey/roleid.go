package devicekey

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// Role is one of a device's two roles for an instance (D2).
type Role int

const (
	Reader Role = 1
	Writer Role = 2
)

// String is "reader" or "writer"; anything else is "Role(<n>)".
func (r Role) String() string {
	switch r {
	case Reader:
		return "reader"
	case Writer:
		return "writer"
	}
	return "Role(" + strconv.Itoa(int(r)) + ")"
}

// valid reports whether r is Reader or Writer.
func (r Role) valid() bool { return r == Reader || r == Writer }

// roleIDText is the fixed text every formatting of a RoleID gives.
const roleIDText = "role ID (not printed)"

// roleIDLen is a role ID's length in bytes: 128 bits.
const roleIDLen = 16

// RoleID is a role's ID: 128 random bits, written as 32 lowercase hex
// characters (D2). It is the CN of the role's anchor and leaf, and the subject
// of the role's principal. Its value sits behind a pointer, so it never
// formats: the methods below cover a RoleID that fmt can reach as an
// interface, and fmt prints a pointer it reaches by reflection, inside an
// unexported field, as an address. Every fmt verb, slog and encoding/json give
// "role ID (not printed)", an address, or {}. Compare with Equal, not ==.
//
// The value is two pointers deep, not one. Under a verb a pointer does not
// take (%s, %q), fmt's badVerb prints the pointer again at depth 0
// (go1.27.4 src/fmt/print.go:384-387), and at depth 0 fmt dereferences a
// pointer to an array or a struct (:905-910): one pointer would print the
// ID's bytes there. A pointer to a pointer is printed as an address at every
// depth.
//
// NewRoleID and ParseRoleID each allocate a fresh array, and nothing hands
// the pointer out. RoleID defines no MarshalText and no MarshalJSON. It is
// not derived from a key, a name or a counter (D2), and it is kept across
// anchor renewals.
type RoleID struct{ p **[roleIDLen]byte }

// roleIDOf holds b as a RoleID, in a fresh array.
func roleIDOf(b *[roleIDLen]byte) RoleID {
	a := new([roleIDLen]byte)
	*a = *b
	return RoleID{p: &a}
}

// bytes is the ID's value; nil for the zero RoleID.
func (id RoleID) bytes() *[roleIDLen]byte {
	if id.p == nil {
		return nil
	}
	return *id.p
}

// NewRoleID reads exactly 16 bytes from rnd (io.ReadFull) and refuses an
// all-zero draw. It reads nothing else.
func NewRoleID(rnd io.Reader) (RoleID, error) {
	if rnd == nil {
		return RoleID{}, errors.New("devicekey: a role ID needs a random source")
	}
	var b [roleIDLen]byte
	if _, err := io.ReadFull(rnd, b[:]); err != nil {
		return RoleID{}, fmt.Errorf("devicekey: draw a role ID: %w", err)
	}
	if b == ([roleIDLen]byte{}) {
		return RoleID{}, errors.New("devicekey: the random source gave an all-zero role ID")
	}
	return roleIDOf(&b), nil
}

// errRoleIDShape is ParseRoleID's one error. It never quotes its input.
var errRoleIDShape = errors.New("devicekey: a role ID is exactly 32 lowercase hexadecimal characters")

// ParseRoleID accepts exactly ^[0-9a-f]{32}$. Its error never quotes s.
func ParseRoleID(s string) (RoleID, error) {
	if len(s) != 2*roleIDLen {
		return RoleID{}, errRoleIDShape
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return RoleID{}, errRoleIDShape
		}
	}
	var b [roleIDLen]byte
	if _, err := hex.Decode(b[:], []byte(s)); err != nil {
		return RoleID{}, errRoleIDShape
	}
	return roleIDOf(&b), nil
}

// Hex is the value, for a certificate's CN, a condition, a principal or a
// block. Never for printing. It is "" for the zero RoleID.
func (id RoleID) Hex() string {
	b := id.bytes()
	if b == nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// IsZero reports whether id is the zero RoleID, which no draw or parse gives.
func (id RoleID) IsZero() bool {
	return id.p == nil
}

// Equal is byte equality; two zero IDs are equal.
func (id RoleID) Equal(o RoleID) bool {
	a, b := id.bytes(), o.bytes()
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// String is "role ID (not printed)".
func (id RoleID) String() string { return roleIDText }

// GoString is "role ID (not printed)".
func (id RoleID) GoString() string { return roleIDText }

// Format writes "role ID (not printed)" for every verb.
func (id RoleID) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, roleIDText) }

// LogValue is slog.StringValue("role ID (not printed)").
func (id RoleID) LogValue() slog.Value { return slog.StringValue(roleIDText) }
