package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/planck"
)

// Five seams refuse in the package's tests when a test leaves them unset (ADR
// 0023 M2.6, A23-49): the deployer's provider opener; the image builder of
// the deployer commands, run and build; connect's dial of the carrier; and
// the deployer's search for a farcast checkout and its question to that
// checkout's Go, which runs `go env` from PATH. Their defaults refuse here,
// as defaultPinStore's does (storagepin_test.go), so no test reaches a real
// provider, registry or carrier, runs this machine's Go, or binds the
// checkout it runs in, through these by forgetting a fake; a test that
// drives a command past one sets the seam to a fake of its own, or, through
// the router, takes fakeDeployDefaults. Other seams keep their real
// defaults, and some commands open a provider, storage or a tunnel directly,
// so this guard is no wider than the five.

// errRefusingDefault is what a default seam answers in a test.
var errRefusingDefault = errors.New("test: a seam was left at its default, which no test may reach; set it to a fake")

func init() {
	openProviderDefault = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		return nil, errRefusingDefault
	}
	newBuilderDefault = func(func(string)) imageBuilder { return refusingBuilder{} }
	connectDialDefault = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		return nil, errRefusingDefault
	}
	findSourceDefault = func(string) (string, error) { return "", errRefusingDefault }
	findToolchainDefault = func(context.Context, []string, string) (image.Toolchain, error) {
		return image.Toolchain{}, errRefusingDefault
	}
}

// refusingBuilder is the image builder a test gets by default: every call
// refuses, and nothing is resolved, built or pushed.
type refusingBuilder struct{}

func (refusingBuilder) Resolve(context.Context, string, string, string) (string, error) {
	return "", errRefusingDefault
}

func (refusingBuilder) BuildAndPush(context.Context, image.Options, string, string) (image.Pushed, error) {
	return image.Pushed{}, errRefusingDefault
}

func (refusingBuilder) PushEmbedded(context.Context, image.EmbeddedOptions, string, string) (image.Pushed, error) {
	return image.Pushed{}, errRefusingDefault
}

// TestUnsetSeamsRefuseInTests: every command whose provider, builder, dial,
// checkout or Go seam is left unset gets the refusing default, never the
// real one.
func TestUnsetSeamsRefuseInTests(t *testing.T) {
	var d fatlineDeployer
	d.ensureDefaults()
	// A provider no adapter registers, so that even the real opener would
	// refuse it at once, before any credential is looked for.
	meta := &config.InstanceMetadata{Name: "atlas", Provider: "unregistered-test-provider"}
	if _, err := d.openProvider(meta, &config.InstanceCredentials{Provider: meta.Provider, ServiceAccountKey: "{}"}); !errors.Is(err, errRefusingDefault) {
		t.Errorf("fatlineDeployer's default provider opener = %v, want the refusing default", err)
	}

	run, build := &runCommand{}, &buildCommand{}
	run.ensureDefaults()
	build.ensureDefaults()
	for name, b := range map[string]imageBuilder{
		"fatlineDeployer": d.newBuilder(nil),
		"run":             run.newBuilder(nil),
		"build":           build.newBuilder(nil),
	} {
		// The type first, so that a real builder is never called here.
		if _, ok := b.(refusingBuilder); !ok {
			t.Errorf("%s's default builder is a %T, not the refusing default", name, b)
			continue
		}
		if _, err := b.Resolve(t.Context(), "example.invalid/x:1", "", ""); !errors.Is(err, errRefusingDefault) {
			t.Errorf("%s's default builder Resolve = %v, want the refusing default", name, err)
		}
		if _, err := b.BuildAndPush(t.Context(), image.Options{}, "", ""); !errors.Is(err, errRefusingDefault) {
			t.Errorf("%s's default builder BuildAndPush = %v, want the refusing default", name, err)
		}
		if _, err := b.PushEmbedded(t.Context(), image.EmbeddedOptions{}, "", ""); !errors.Is(err, errRefusingDefault) {
			t.Errorf("%s's default builder PushEmbedded = %v, want the refusing default", name, err)
		}
	}

	// connect's dial, with a context already cancelled and a TEST-NET-1
	// address (RFC 5737), so that even the real dial sends nothing.
	conn := newConnectCommand()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := conn.dial(cancelled, "https://192.0.2.10:8443", tunnel.ClientIdentity{}); !errors.Is(err, errRefusingDefault) {
		t.Errorf("connect's default dial = %v, want the refusing default", err)
	}

	// The checkout and its Go, asked from an empty directory with a PATH
	// that holds no go, so that even the real ones find nothing and run
	// nothing.
	empty := t.TempDir()
	if _, err := d.findSource(empty); !errors.Is(err, errRefusingDefault) {
		t.Errorf("fatlineDeployer's default findSource = %v, want the refusing default", err)
	}
	if _, err := d.findToolchain(t.Context(), []string{"PATH=" + empty}, empty); !errors.Is(err, errRefusingDefault) {
		t.Errorf("fatlineDeployer's default findToolchain = %v, want the refusing default", err)
	}
}
