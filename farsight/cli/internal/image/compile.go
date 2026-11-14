package image

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Binary is a compiled component and the Go release that compiled it.
type Binary struct {
	Data      []byte
	GoVersion string // from the binary's own build info
}

// GoCompile is the default Builder.Compile, goCompile. It is exported so that
// farcast-release's tests can show that the release's component build and this
// one give the same bytes for the same source.
func GoCompile(ctx context.Context, sourceDir, pkg string) (Binary, error) {
	return goCompile(ctx, sourceDir, pkg)
}

// goCompile is the default Builder.Compile: it cross-compiles pkg inside
// sourceDir for ComponentPlatform with the recipe in recipe.go.
//
// It is the operator's own patch path (--source) and the development fallback
// of a farcast that carries no components. A release farcast pushes the layers
// it carries instead and needs no Go at all (ADR 0023 decision 4).
//
// The Go is the operator's choice: whichever go is on PATH, asked where its
// toolchain lives, so that a version manager's shim works. It is refused when it
// is older than the checkout's go.mod toolchain line, and a newer one is used as
// it is (ADR 0023 decision 6). Nothing is ever downloaded: the build runs with
// GOTOOLCHAIN=local, GOPROXY=off and -mod=vendor. Nothing is inherited either:
// the build's environment is BuildEnviron's allowlist, so a GOFLAGS, a go env
// file, a GOCACHEPROG or a GIT_DIR in the operator's shell cannot change or
// stamp what is built, and CheckBinary verifies the result.
func goCompile(ctx context.Context, sourceDir, pkg string) (Binary, error) {
	tc, err := FindToolchain(ctx, os.Environ(), sourceDir)
	if errors.Is(err, ErrNoGo) {
		return Binary{}, &wrapped{
			msg: "image: building a component from source needs the Go toolchain on PATH (a release farcast needs none: it carries its components)",
			err: ErrNoGo,
		}
	}
	if err != nil {
		return Binary{}, fmt.Errorf("%w (a version manager's shim on PATH must resolve to a Go for %s)", err, sourceDir)
	}
	floor, err := ToolchainFloor(sourceDir)
	if err != nil {
		return Binary{}, err
	}
	if err := checkFloor(tc.Go, tc.Version, floor); err != nil {
		return Binary{}, err
	}

	dir, err := os.MkdirTemp("", "farcast-image-")
	if err != nil {
		return Binary{}, fmt.Errorf("image: create build directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	out := filepath.Join(dir, "binary")
	cmd := exec.CommandContext(ctx, tc.Go, BuildFlags(out, pkg)...)
	cmd.Dir = sourceDir
	cmd.Env = BuildEnviron(os.Environ(), tc, "local", "")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return Binary{}, fmt.Errorf("image: go build %s: %s", pkg, msg)
		}
		return Binary{}, fmt.Errorf("image: go build %s: %w", pkg, err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return Binary{}, fmt.Errorf("image: read compiled binary: %w", err)
	}
	v, err := CheckBinary(data)
	if err != nil {
		return Binary{}, fmt.Errorf("image: %s: %w", pkg, err)
	}
	if v != tc.Version {
		return Binary{}, fmt.Errorf("image: %s reported %s but built with %s", tc.Go, tc.Version, v)
	}
	return Binary{Data: data, GoVersion: v}, nil
}

// wrapped is an error with its own message that still matches a sentinel.
type wrapped struct {
	msg string
	err error
}

func (w *wrapped) Error() string { return w.msg }
func (w *wrapped) Unwrap() error { return w.err }
