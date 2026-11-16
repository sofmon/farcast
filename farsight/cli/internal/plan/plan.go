// Package plan is the consent protocol's document (ADR 0023 decision 8, M2.6):
// what a command that writes to a cluster would do, encoded canonically, so
// that one digest stands for everything the operator read.
//
// A command computes a Bound from live state and prints it with --plan. Under
// --confirm <digest> it computes the Bound again, and executes only when the
// new digest is the one it was given. The digest is taken over Canonical's
// bytes, and a printed Document carries exactly those bytes, so a reader can
// hash what was printed and compare.
//
// The package is the standard library only, and imports nothing from the CLI:
// the CLI imports it. Money reaches a fact as integer cents (the CLI's cents),
// and the CLI's build stamp converts to Stamp.
package plan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// Protocol names the encoding and the digest rule. It is bound in every
	// plan and prefixes every digest's input, so a plan of another protocol
	// can never confirm this one.
	Protocol = "farcast-plan-1"
	// Schema and Kind open every printed Document.
	Schema = 1
	Kind   = "plan"
)

// Bound is everything a plan binds: its digest covers these fields, in this
// order, every one always present (§9.3).
type Bound struct {
	Protocol string `json:"protocol"`
	// FarCast is the farcast that computed the plan, so a bundled and a
	// terminal farcast cannot confirm each other's plans.
	FarCast Stamp  `json:"farcast"`
	Command string `json:"command"` // "kernel deploy"
	// Instance is a local name only: Target says which instance it is.
	Instance string `json:"instance"`
	Target   Target `json:"target"`
	Stage    string `json:"stage"` // "" except run: "fetch" | "deploy"
	// Options are the flags that change behaviour, strictly ascending by Flag.
	Options []Option `json:"options"`
	// ClusterIdentity is who the plan reads the cluster as: "reader", "writer"
	// or "none", fixed per command and state.
	ClusterIdentity string `json:"cluster_identity"`
	// Facts are in the order the command presents them.
	Facts []Fact `json:"facts"`
	// Blocked is [] when nothing refuses the plan. A blocked plan's Facts are
	// [], since computation stops at the first block.
	Blocked []Block `json:"blocked"`
}

// Target is which instance the plan is about, read from the record, and, where
// the plan reads the cluster, from the cluster: a plan reviewed against one
// config directory, project or cluster cannot be confirmed against another.
// Its values are the record's own, unscrubbed (A23-4).
type Target struct {
	Provider string `json:"provider"`
	Project  string `json:"project"`
	Region   string `json:"region"`
	Cluster  string `json:"cluster"`
	Endpoint string `json:"endpoint"`
	// CreatedAt is the record's creation time, through Time.
	CreatedAt string `json:"created_at"`
	// SystemNamespaceUID is farcast-system's uid; "" when the plan reads no
	// cluster, or when farcast-system does not exist yet.
	SystemNamespaceUID string `json:"system_namespace_uid"`
}

// Stamp is the farcast that computed a plan. Its fields are the CLI's build
// stamp's, in the same order, so the CLI converts one into the other (A23-29).
type Stamp struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Option is one behaviour-changing flag and its parsed value.
type Option struct {
	Flag  string `json:"flag"`
	Value string `json:"value"`
}

// Block is a refusal the plan carries in place of its facts: --plan prints it,
// and --confirm refuses with its kind and message. Kind is one of the CLI's
// error kinds.
type Block struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// Fact is one thing a plan says the command would do. Every fact type is a
// struct whose first field is `Type string` holding FactType()'s word.
type Fact interface{ FactType() string }

// Document is a printed plan. Bound holds Canonical's bytes verbatim, so its
// digest can be checked by hashing the member as printed.
type Document struct {
	Schema      int             `json:"schema"`
	Kind        string          `json:"kind"`
	GeneratedAt string          `json:"generated_at"`
	Digest      string          `json:"digest"`
	Bound       json.RawMessage `json:"bound"`
}

// Canonical is the one encoding a plan's digest is taken over: encoding/json
// without HTML escaping and without the trailing newline, with every nil slice
// written as [] rather than null, so a plan built with an empty slice and one
// built with a nil one are the same plan.
//
// It refuses a Bound of another protocol, options that are not strictly
// ascending by flag, a fact whose Type field is not its FactType(), and any
// string that is not valid UTF-8: encoding/json writes each invalid byte as
// U+FFFD, so two plans that differ only there would have one digest.
func Canonical(b Bound) ([]byte, error) {
	if b.Protocol != Protocol {
		return nil, fmt.Errorf("plan: the protocol is %q, not %q", b.Protocol, Protocol)
	}
	for i := 1; i < len(b.Options); i++ {
		if b.Options[i-1].Flag >= b.Options[i].Flag {
			return nil, fmt.Errorf("plan: the options are not strictly ascending by flag: %q comes after %q",
				b.Options[i].Flag, b.Options[i-1].Flag)
		}
	}
	for i, f := range b.Facts {
		if err := checkFactType(i, f); err != nil {
			return nil, err
		}
	}

	copied, err := withEmptySlices(reflect.ValueOf(b), "bound")
	if err != nil {
		return nil, err
	}
	normalized := copied.Interface()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalized); err != nil {
		return nil, fmt.Errorf("plan: encode the plan: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// checkFactType refuses a fact whose Type field, its first, is not the word
// its FactType method gives: two sources for one value must not disagree.
func checkFactType(i int, f Fact) error {
	if f == nil {
		return fmt.Errorf("plan: fact %d is nil", i)
	}
	v := reflect.ValueOf(f)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return fmt.Errorf("plan: fact %d is a nil %T", i, f)
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("plan: fact %d is a %T, not a struct", i, f)
	}
	if v.NumField() == 0 || v.Type().Field(0).Name != "Type" || v.Field(0).Kind() != reflect.String {
		return fmt.Errorf("plan: fact %d, a %T, does not begin with a string Type field", i, f)
	}
	if got, want := v.Field(0).String(), f.FactType(); got != want {
		return fmt.Errorf("plan: fact %d is a %q fact, but its type field says %q", i, want, got)
	}
	return nil
}

// withEmptySlices returns a deep copy of v in which every nil slice is an empty
// one. The caller's value is never changed: a plan's facts may share slices
// with the command that built them. It refuses a string that is not valid
// UTF-8, naming where it is by path (bound.target.project, bound.facts[2].text)
// and never quoting it.
func withEmptySlices(v reflect.Value, path string) (reflect.Value, error) {
	switch v.Kind() {
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return reflect.Value{}, fmt.Errorf("plan: %s is not valid UTF-8", path)
		}
		return v, nil
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" {
				name = f.Name
			}
			c, err := withEmptySlices(v.Field(i), path+"."+name)
			if err != nil {
				return reflect.Value{}, err
			}
			out.Field(i).Set(c)
		}
		return out, nil
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return reflect.MakeSlice(v.Type(), 0, 0), nil
		}
		var out reflect.Value
		if v.Kind() == reflect.Slice {
			out = reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		} else {
			out = reflect.New(v.Type()).Elem()
		}
		for i := 0; i < v.Len(); i++ {
			c, err := withEmptySlices(v.Index(i), path+"["+strconv.Itoa(i)+"]")
			if err != nil {
				return reflect.Value{}, err
			}
			out.Index(i).Set(c)
		}
		return out, nil
	case reflect.Pointer:
		if v.IsNil() {
			return v, nil
		}
		c, err := withEmptySlices(v.Elem(), path)
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(c)
		return out, nil
	case reflect.Interface:
		if v.IsNil() {
			return v, nil
		}
		c, err := withEmptySlices(v.Elem(), path)
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(c)
		return out, nil
	default:
		// Other scalars are copied by value. Maps are never in a plan's
		// types (TestFactTypesAreCanonical), so none is walked.
		return v, nil
	}
}

const digestPrefix = "sha256:"

// DigestOf is a plan's digest: "sha256:" and the lowercase hex SHA-256 of the
// protocol's name, a newline, and the canonical bytes. The prefix separates a
// plan's digest from a hash of the same bytes taken for any other purpose.
func DigestOf(canonical []byte) string {
	h := sha256.New()
	h.Write([]byte(Protocol + "\n"))
	h.Write(canonical)
	return digestPrefix + hex.EncodeToString(h.Sum(nil))
}

var digestShape = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ParseDigest accepts a digest exactly as DigestOf writes it, and nothing
// else: no uppercase, no other prefix, no surrounding space. Its refusal does
// not repeat the input, which may be anything the operator pasted.
func ParseDigest(s string) (string, error) {
	if !digestShape.MatchString(s) {
		return "", errors.New("plan: a plan digest is sha256: and 64 lowercase hex characters")
	}
	return s, nil
}

// NewDocument is the printed form of b, generated at now.
func NewDocument(b Bound, now time.Time) (Document, error) {
	c, err := Canonical(b)
	if err != nil {
		return Document{}, err
	}
	return Document{
		Schema:      Schema,
		Kind:        Kind,
		GeneratedAt: Time(now),
		Digest:      DigestOf(c),
		Bound:       json.RawMessage(c),
	}, nil
}

// Time is a time as a plan writes it: UTC, whole seconds, RFC 3339 — the CLI's
// wire-time rule, for created_at and generated_at.
func Time(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}
