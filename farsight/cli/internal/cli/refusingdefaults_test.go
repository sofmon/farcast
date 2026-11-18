package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/planck"
)

// Eight seams refuse in the package's tests when a test leaves them unset
// (ADR 0023 M2.6, A23-49, A25-20): the deployer's provider opener; the image
// builder of the deployer commands, run and build; connect's dial of the
// carrier; the deployer's search for a farcast checkout and its question to
// that checkout's Go, which runs `go env` from PATH; the reader a plan reads
// the cluster as (openReaderDefault, M2.6c), which run's plan reader wraps,
// lazily, since M2.6d; storage deploy's mint of the bucket and keyring
// (ensureStorageDefault, M2.6c); and the opener of the keyholder of storage
// key pin, storage key rotate and, since M2.6d, run, which dials the tunnel
// (openKeyholderDefault, M2.6c); run's uses of the two add no ninth seam
// (A28-11). Their defaults refuse here, as defaultPinStore's does
// (storagepin_test.go), so no test reaches a real provider, registry,
// carrier, cluster, bucket or keyholder, runs this machine's Go, or binds
// the checkout it runs in, through these by forgetting a fake; a test that
// drives a command past one sets the seam to a fake of its own, or, through
// the router, takes fakeDeployDefaults. Other seams keep their real
// defaults, and some commands open a provider, storage or a tunnel directly,
// so this guard is no wider than the eight.

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
	openReaderDefault = func(clusterRef) (*cluster.Client, error) { return nil, errRefusingDefault }
	ensureStorageDefault = func(context.Context, *Env, string) error { return errRefusingDefault }
	openKeyholderDefault = func(context.Context, *Env, string) (sealStateClient, func(), error) {
		return nil, nil, errRefusingDefault
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
// checkout, Go, plan reader, storage mint or keyholder seam is left unset
// gets the refusing default, never the real one.
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

	// The reader each plan that reads the cluster opens, for a record that
	// names no endpoint, so that even the real reader would refuse it before
	// anything is sent (ADR 0023 M2.6c).
	readerRef := clusterRef{Dir: config.Dir(empty), Meta: meta, Identity: kube.Reader}
	kd := &kernelDeployCommand{}
	kd.ensureDefaults()
	if _, err := kd.newPlanReader(readerRef); !errors.Is(err, errRefusingDefault) {
		t.Errorf("kernel deploy's default plan reader = %v, want the refusing default", err)
	}
	sd, kp, kr := &storageDeployCommand{}, &keyPinCommand{}, &keyRotateCommand{}
	sd.ensureDefaults()
	kp.ensureDefaults()
	kr.ensureDefaults()
	for name, open := range map[string]func(clusterRef) (pinPlanReader, error){
		"storage deploy": sd.newPlanReader, "storage key pin": kp.newPlanReader, "storage key rotate": kr.newPlanReader,
	} {
		if rd, err := open(readerRef); !errors.Is(err, errRefusingDefault) || rd != nil {
			t.Errorf("%s's default plan reader = %v, %v; want the refusing default", name, rd, err)
		}
	}
	// run's, which wraps openReaderDefault when it is called (A28-11), and
	// so refuses with it, returning no reader.
	if rd, err := run.newPlanReader(readerRef); !errors.Is(err, errRefusingDefault) || rd != nil {
		t.Errorf("run's default plan reader = %v, %v; want the refusing default", rd, err)
	}

	// storage deploy's mint of the bucket and keyring, for an instance this
	// directory has no record of, so that even the real mint would refuse
	// it before any cloud is reached; and the keyholder of storage key pin
	// and storage key rotate, with a context already cancelled, for the
	// same instance.
	if err := sd.ensureStorage(cancelled, &Env{ConfigDir: config.Dir(empty)}, "atlas"); !errors.Is(err, errRefusingDefault) {
		t.Errorf("storage deploy's default storage mint = %v, want the refusing default", err)
	}
	for name, open := range map[string]keyholderOpener{"storage key pin": kp.newKeyholder, "storage key rotate": kr.newKeyholder, "run": run.newKeyholder} {
		if _, _, err := open(cancelled, &Env{ConfigDir: config.Dir(empty)}, "atlas"); !errors.Is(err, errRefusingDefault) {
			t.Errorf("%s's default keyholder = %v, want the refusing default", name, err)
		}
	}
}
