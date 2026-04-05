// Package parser provides the ./farcast manifest parser.
//
// It decodes and validates a ./farcast YAML manifest against the
// specification in manifest/README.md. Parse returns the parsed manifest
// and/or an error aggregating every validation failure discovered.
package parser

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
)

// Manifest is a parsed and validated ./farcast manifest.
type Manifest struct {
	Name string
	Apps []App
}

// App is one application entry in a manifest.
type App struct {
	Name          string
	Containerfile string
	Context       string     // empty when omitted
	External      []External // nil when omitted
}

// External is one declared outbound endpoint for an app.
type External struct {
	Host   string
	Reason string
}

// ErrInvalidManifest is the sentinel wrapper for every validation failure.
// Use errors.Is(err, parser.ErrInvalidManifest) to detect parser errors.
var ErrInvalidManifest = errors.New("invalid manifest")

// FieldError describes one validation failure at a specific path in the
// manifest document.
type FieldError struct {
	Path    string // dotted/indexed path, e.g. "apps[1].external[0].host"
	Message string
}

func (e *FieldError) Error() string {
	if e.Path == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

func (e *FieldError) Is(target error) bool {
	return target == ErrInvalidManifest
}

// newFieldError is a small helper that keeps validation sites terse.
func newFieldError(path, format string, args ...any) *FieldError {
	return &FieldError{Path: path, Message: fmt.Sprintf(format, args...)}
}

// --- Raw decode targets ---------------------------------------------------
//
// Pointer fields let us distinguish "key absent" from "key present with a
// zero/null value" — the spec treats these differently for several rules
// (e.g. apps missing vs apps: [] vs apps: null).

type rawManifest struct {
	Name *string   `yaml:"name"`
	Apps *[]rawApp `yaml:"apps"`
}

type rawApp struct {
	Name          *string        `yaml:"name"`
	Containerfile *string        `yaml:"containerfile"`
	Context       *string        `yaml:"context"`
	External      *[]rawExternal `yaml:"external"`
}

type rawExternal struct {
	Host   *string `yaml:"host"`
	Reason *string `yaml:"reason"`
}

// --- Public API -----------------------------------------------------------

// Parse validates and decodes a ./farcast manifest from raw bytes.
// All validation errors are aggregated via errors.Join. On success, the
// returned error is nil. On failure, the returned *Manifest is nil.
func Parse(data []byte) (*Manifest, error) {
	// Strip a UTF-8 BOM if present. The spec says the file is UTF-8, and a
	// BOM is legal but most YAML parsers treat it as part of the first key.
	data = bytes.TrimPrefix(data, []byte("\uFEFF"))

	// Empty document (rule 2): catch before handing to the YAML library so
	// the error message is precise and not a cryptic "EOF".
	if isBlank(data) {
		return nil, errors.Join(
			ErrInvalidManifest,
			&FieldError{Message: "manifest is empty"},
		)
	}

	var raw rawManifest
	// Strict() rejects unknown keys at every level in a single pass —
	// covers rules 3 (top-level), 16 (per-app), and 26 (per-external).
	if err := yaml.UnmarshalWithOptions(data, &raw, yaml.Strict()); err != nil {
		// Wrap the YAML library error. goccy already includes line/col
		// and a source snippet in its Error() output.
		return nil, errors.Join(
			ErrInvalidManifest,
			&FieldError{Message: "yaml: " + err.Error()},
		)
	}

	m, errs := validate(&raw)
	if len(errs) > 0 {
		joined := make([]error, 0, len(errs)+1)
		joined = append(joined, ErrInvalidManifest)
		for _, e := range errs {
			joined = append(joined, e)
		}
		return nil, errors.Join(joined...)
	}
	return m, nil
}

// ParseFile reads the file at path and parses it as a ./farcast manifest.
func ParseFile(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// isBlank reports whether data contains only whitespace, BOM, and YAML
// comments (lines starting with #). Such a document carries no keys and
// would otherwise surface as "name missing, apps missing" — the spec
// prefers a clearer "empty" error.
func isBlank(data []byte) bool {
	s := strings.TrimPrefix(string(data), "\uFEFF")
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return false
	}
	return true
}

// --- Validation -----------------------------------------------------------

func validate(raw *rawManifest) (*Manifest, []error) {
	var errs []error
	m := &Manifest{}

	// Top-level name (rules 4–10).
	if raw.Name == nil {
		errs = append(errs, newFieldError("name", "is required"))
	} else {
		if err := validateDNSLabel(*raw.Name, "name"); err != nil {
			errs = append(errs, err)
		} else {
			m.Name = *raw.Name
		}
	}

	// Top-level apps (rules 11–14).
	if raw.Apps == nil {
		errs = append(errs, newFieldError("apps", "is required"))
		return nil, errs
	}
	if len(*raw.Apps) == 0 {
		errs = append(errs, newFieldError("apps", "must contain at least one app"))
		return nil, errs
	}

	seenAppNames := make(map[string]int, len(*raw.Apps))
	m.Apps = make([]App, 0, len(*raw.Apps))
	for i, rawApp := range *raw.Apps {
		path := fmt.Sprintf("apps[%d]", i)
		app, appErrs := validateApp(&rawApp, path)
		errs = append(errs, appErrs...)

		// Duplicate app-name detection (rule 14). Only meaningful if the
		// name itself validated.
		if rawApp.Name != nil && *rawApp.Name != "" {
			if prev, ok := seenAppNames[*rawApp.Name]; ok {
				errs = append(errs, newFieldError(
					fmt.Sprintf("%s.name", path),
					"duplicate app name %q (first defined at apps[%d])",
					*rawApp.Name, prev,
				))
			} else {
				seenAppNames[*rawApp.Name] = i
			}
		}
		if app != nil {
			m.Apps = append(m.Apps, *app)
		}
	}

	if len(errs) > 0 {
		return nil, errs
	}
	return m, nil
}

func validateApp(raw *rawApp, path string) (*App, []error) {
	var errs []error
	app := &App{}

	// name (rule 17).
	if raw.Name == nil {
		errs = append(errs, newFieldError(path+".name", "is required"))
	} else if err := validateDNSLabel(*raw.Name, path+".name"); err != nil {
		errs = append(errs, err)
	} else {
		app.Name = *raw.Name
	}

	// containerfile (rules 18–20).
	if raw.Containerfile == nil {
		errs = append(errs, newFieldError(path+".containerfile", "is required"))
	} else if err := validateRelPath(*raw.Containerfile, path+".containerfile"); err != nil {
		errs = append(errs, err)
	} else {
		app.Containerfile = *raw.Containerfile
	}

	// context (rules 21–23). Optional.
	if raw.Context != nil {
		if err := validateRelPath(*raw.Context, path+".context"); err != nil {
			errs = append(errs, err)
		} else {
			app.Context = *raw.Context
		}
	}

	// external (rules 24–30). Optional.
	if raw.External != nil {
		seenHosts := make(map[string]int, len(*raw.External))
		app.External = make([]External, 0, len(*raw.External))
		for i, rawExt := range *raw.External {
			extPath := fmt.Sprintf("%s.external[%d]", path, i)
			ext, extErrs := validateExternal(&rawExt, extPath)
			errs = append(errs, extErrs...)

			if rawExt.Host != nil && *rawExt.Host != "" {
				if prev, ok := seenHosts[*rawExt.Host]; ok {
					errs = append(errs, newFieldError(
						extPath+".host",
						"duplicate host %q within this app (first defined at %s.external[%d])",
						*rawExt.Host, path, prev,
					))
				} else {
					seenHosts[*rawExt.Host] = i
				}
			}
			if ext != nil {
				app.External = append(app.External, *ext)
			}
		}
	}

	if len(errs) > 0 {
		return nil, errs
	}
	return app, nil
}

func validateExternal(raw *rawExternal, path string) (*External, []error) {
	var errs []error
	ext := &External{}

	// host (rules 27–28).
	if raw.Host == nil {
		errs = append(errs, newFieldError(path+".host", "is required"))
	} else if err := validateHostname(*raw.Host, path+".host"); err != nil {
		errs = append(errs, err)
	} else {
		ext.Host = *raw.Host
	}

	// reason (rule 29).
	if raw.Reason == nil {
		errs = append(errs, newFieldError(path+".reason", "is required"))
	} else if *raw.Reason == "" {
		errs = append(errs, newFieldError(path+".reason", "must not be empty"))
	} else {
		ext.Reason = *raw.Reason
	}

	if len(errs) > 0 {
		return nil, errs
	}
	return ext, nil
}

// --- Scalar validators ----------------------------------------------------

// validateDNSLabel enforces the regex /^[a-z][a-z0-9-]{0,61}[a-z0-9]$/
// with the single-character edge case (one lowercase letter is allowed).
// Used for both the top-level deployment name and each app name.
func validateDNSLabel(s, path string) error {
	if s == "" {
		return newFieldError(path, "must not be empty")
	}
	if len(s) > 63 {
		return newFieldError(path, "must be at most 63 characters (got %d)", len(s))
	}
	first := s[0]
	if !(first >= 'a' && first <= 'z') {
		return newFieldError(path, "must start with a lowercase letter (a-z)")
	}
	if len(s) == 1 {
		return nil
	}
	last := s[len(s)-1]
	if last == '-' {
		return newFieldError(path, "must not end with a hyphen")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return newFieldError(path, "must contain only lowercase letters, digits, and hyphens (invalid character %q at index %d)", string(c), i)
		}
	}
	return nil
}

// validateRelPath enforces that a path is non-empty, relative (no leading
// slash), and contains no ".." segments. We deliberately do not use
// filepath.Clean — it silently collapses ".." against earlier segments,
// which would hide escape attempts like "./a/../../b".
func validateRelPath(s, path string) error {
	if s == "" {
		return newFieldError(path, "must not be empty")
	}
	if strings.HasPrefix(s, "/") {
		return newFieldError(path, "must be a relative path (got absolute %q)", s)
	}
	// Reject backslash-prefixed paths too — YAML is cross-platform, but
	// manifest paths use POSIX separators.
	if strings.HasPrefix(s, `\`) {
		return newFieldError(path, "must be a relative path (got absolute %q)", s)
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == ".." {
			return newFieldError(path, "must not contain %q segment", "..")
		}
	}
	return nil
}

// validateHostname enforces: non-empty; total length ≤ 253; each
// dot-separated label 1–63 chars, alphanumeric with internal hyphens;
// no scheme, port, path, wildcards, or IP literals.
func validateHostname(s, path string) error {
	if s == "" {
		return newFieldError(path, "must not be empty")
	}
	if strings.Contains(s, "://") {
		return newFieldError(path, "must not include a URL scheme")
	}
	if strings.ContainsAny(s, ":/") {
		return newFieldError(path, "must not include a port or path")
	}
	if strings.Contains(s, "*") {
		return newFieldError(path, "wildcards are not allowed")
	}
	if strings.Contains(s, " ") {
		return newFieldError(path, "must not contain whitespace")
	}
	if ip := net.ParseIP(s); ip != nil {
		return newFieldError(path, "IP addresses are not allowed")
	}
	if len(s) > 253 {
		return newFieldError(path, "must be at most 253 characters (got %d)", len(s))
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return newFieldError(path, "must not start or end with a dot")
	}
	for _, label := range strings.Split(s, ".") {
		if err := validateHostnameLabel(label, path); err != nil {
			return err
		}
	}
	return nil
}

func validateHostnameLabel(label, path string) error {
	if len(label) == 0 {
		return newFieldError(path, "contains an empty DNS label")
	}
	if len(label) > 63 {
		return newFieldError(path, "DNS label %q is longer than 63 characters", label)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return newFieldError(path, "DNS label %q must not start or end with a hyphen", label)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return newFieldError(path, "DNS label %q contains invalid character %q", label, string(c))
		}
	}
	return nil
}
