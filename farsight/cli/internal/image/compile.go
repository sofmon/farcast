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

// goCompile is the default Builder.Compile: it cross-compiles pkg inside
// sourceDir for the target platform using the local Go toolchain.
//
// This is the one subprocess in the image path, and it is deliberately the
// smallest thing that can be: no flags beyond what hermeticity requires, no
// credentials, no state outside a temporary directory it removes. The build is
// hermetic by construction — CGO off so the binary is static and needs no libc
// in the base, -mod=vendor so no module is fetched from the network, and -trimpath
// so absolute paths from the operator's machine do not end up inside the image
// FarCast publishes.
//
// The Go toolchain is the only external tool the image path needs, and it is
// already a prerequisite for having a farcast binary at all (source-first
// distribution), so this adds nothing to what an operator must install.
//
// One caveat, deliberately not hidden: go.mod pins an exact toolchain, so on a
// machine whose Go is older the go command fetches that toolchain once, through
// the checksum-verified module proxy. The build itself still fetches nothing —
// and the pin is what makes this build and fatline/Containerfile's reference
// build use the same compiler.
func goCompile(ctx context.Context, sourceDir, pkg string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "farcast-image-")
	if err != nil {
		return nil, fmt.Errorf("image: create build directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	out := filepath.Join(dir, "binary")
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-mod=vendor", "-o", out, pkg)
	cmd.Dir = sourceDir
	// Duplicate keys are resolved last-wins by os/exec, so these override any
	// GOOS/GOARCH/CGO_ENABLED the operator has set for their own machine.
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+targetPlatform.OS, "GOARCH="+targetPlatform.Architecture)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errors.New("image: the Go toolchain is not on PATH — building FarCast's own image needs it")
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("image: go build %s: %s", pkg, msg)
		}
		return nil, fmt.Errorf("image: go build %s: %w", pkg, err)
	}
	binary, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("image: read compiled binary: %w", err)
	}
	return binary, nil
}
