package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/planck"
)

// The plan vectors (ADR 0023 M2.6, A23-29): each command's printed plan, byte
// for byte, made by the command itself through its seams against the atlas
// fixture's record, with this farcast's stamp and clock fixed at the world
// vectors' own. They read no cluster: the commands of M2.6a and M2.6b have
// plans that read none. connect's and redeploy's read the registry, through
// a fake provider and a fake builder whose registry holds neither carried
// image's version tag, as a release farcast at the vector stamp that carries
// the fake components. They are produced in Go and are not copied to
// FarSightKit until ADR 0021 step 7.1. Each part of M2.6 adds the vectors of
// the commands it wires.
//
//	FARCAST_UPDATE_VECTORS=1 go test ./farsight/cli/internal/cli/ -run Vector
//
// rewrites them.

// planVectorMeta is the atlas fixture's record as the plan vectors bind it:
// vectorMeta, which records no creation time, with one.
func planVectorMeta() *config.InstanceMetadata {
	meta := vectorMeta()
	meta.CreatedAt = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	return meta
}

// vectorClock is the plan vectors' clock.
func vectorClock() time.Time { return vectorNow }

// usePlanVectorStamp binds the vector stamp in every plan for the rest of
// the test.
func usePlanVectorStamp(t *testing.T) {
	t.Helper()
	saved := planStamp
	planStamp = func() plan.Stamp { return plan.Stamp(vectorStamp) }
	t.Cleanup(func() { planStamp = saved })
}

// planVector is one command's plan as a vector: the record it is made from,
// and the command, its flags parsed and its clock fixed.
type planVector struct {
	name string
	edit func(meta *config.InstanceMetadata)
	cmd  func(t *testing.T, flags ...string) Command
	args []string
	// flags are the command's own; the vector adds --plan.
	flags []string
	// prepare, when set, writes what the record alone cannot say: the
	// installer's key, for a plan that reads the registry, and the CA
	// certificate, for one that loads the instance's material.
	prepare func(t *testing.T, dir config.Dir)
}

// vectorRevision is the revision the plan vectors' farcast was built at,
// and its carried components with it: the vector stamp's commit, padded to
// a full revision.
const vectorRevision = "0e54eb1" + "000000000000000000000000000000000"

// vectorCACert is the CA certificate the redeploy vector's instance holds:
// the P-256 instance CA of FatLine's PKI fixture
// (fatline/internal/crypto/testdata/pki/p256.json), public test data trusted
// nowhere else. A plan reads this certificate, never a key.
const vectorCACert = `-----BEGIN CERTIFICATE-----
MIIBgTCCASigAwIBAgIBATAKBggqhkjOPQQDAjAnMSUwIwYDVQQDExxGYXJDYXN0
IEluc3RhbmNlIENBOiBmaXh0dXJlMB4XDTI2MTExMjIzNTkwMFoXDTI4MTExMjAw
MDAwMFowJzElMCMGA1UEAxMcRmFyQ2FzdCBJbnN0YW5jZSBDQTogZml4dHVyZTBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABKzz0I4jC96W7jkv8aWX74iKrR+K6VLS
CCY6Z7kgoh83TUg/NwdBbLfv4I3LMHMCoGyJAD3zG6fkzwK39m4kmIOjRTBDMA4G
A1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRfkcan
ANozTsWRo/M0WTCnmTAtUTAKBggqhkjOPQQDAgNHADBEAiBiNjtZwv8ke+G2G4ua
l/Sig68fxXr2d1zabessMsHgfgIgfwhUyL2Kj8TckPDYzuBynlRASMXCH432NYq3
6/j1u9k=
-----END CERTIFICATE-----
`

// vectorDeployer makes d the plan vectors' farcast: a release at the vector
// stamp, built at vectorRevision and carrying the fake components built
// there, its clock the vectors'. Its provider is a fake, and its builder one
// whose registry holds no version tag, so a plan pushes each carried image.
// It finds no checkout, and its writer refuses: a plan opens none.
func vectorDeployer(d *fatlineDeployer) {
	carried := newFakeCarried()
	carried.revision = vectorRevision
	d.carried = carried
	d.build = func() buildinfo.Info {
		return buildinfo.Info{Version: vectorStamp.Version, Commit: vectorStamp.Commit, Date: "2026-11-01T09:00:00Z", Revision: vectorRevision}
	}
	d.now = vectorClock
	d.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		return &fakeProvider{}, nil
	}
	d.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{resolveFn: notFoundForTags} }
	d.findSource = func(string) (string, error) { return "", errors.New("test: the vectors build nothing") }
	d.findToolchain = fakeToolchain
	d.newCluster = func(clusterRef) (clusterApplier, error) { return nil, errors.New("test: a plan opened the writer") }
}

// vectorKey stores the installer's key, a stand-in, for a plan that reads
// the registry with it.
func vectorKey(t *testing.T, dir config.Dir) {
	t.Helper()
	if err := dir.SaveInstanceCredentials("atlas", &config.InstanceCredentials{Provider: "gke", ServiceAccountKey: standInKey}); err != nil {
		t.Fatal(err)
	}
}

// vectorFirstConnect is the atlas record before its first connect: FatLine
// not deployed, no carrier, and no image recorded for FatLine or Shrike.
func vectorFirstConnect(m *config.InstanceMetadata) {
	m.FatLineDeployed, m.Carrier, m.Registry.FatLineDigest = false, nil, ""
	delete(m.SystemImages, "fatline")
	delete(m.SystemImages, "shrike")
}

// vectorRedeployed is the atlas record as a redeploy over another release
// finds it: FatLine and Shrike run images an earlier farcast pushed into the
// registry's system paths, so the plan, made with --embedded, replaces both
// and says so.
func vectorRedeployed(m *config.InstanceMetadata) {
	fl, sh := vecRegistry+"/system/fatline"+digestOf("1"), vecRegistry+"/system/shrike"+digestOf("2")
	m.Registry.FatLineDigest = fl
	m.SystemImages["fatline"] = config.SystemImage{Image: fl, Origin: config.OriginEmbedded, Go: "go1.27.4", Farcast: "v0.0.0-earlier"}
	m.SystemImages["shrike"] = config.SystemImage{Image: sh, Origin: config.OriginEmbedded, Go: "go1.27.4", Farcast: "v0.0.0-earlier"}
}

// vectorMaterial is the redeploy vector's key and CA certificate: the
// instance's material as far as a plan reads it.
func vectorMaterial(t *testing.T, dir config.Dir) {
	t.Helper()
	vectorKey(t, dir)
	if err := dir.SaveInstanceMTLS("atlas", config.MTLSMaterial{CACertPEM: []byte(vectorCACert)}); err != nil {
		t.Fatal(err)
	}
}

// vectorConfirmations is the confirmed window the kernel_confirm vector's
// record already holds, so the plan's windows_after has two.
func vectorConfirmations(m *config.InstanceMetadata) {
	m.Kernel.Confirmations = []config.KernelConfirmation{{
		Start: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC),
		USD: 1.03, AsOf: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC),
	}}
}

func planVectors() []planVector {
	return []planVector{
		{"kernel_meter", nil, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &kernelMeterCommand{}, flags...)
			c.deployer.now = vectorClock
			return c
		}, []string{"atlas", "web"}, nil, nil},
		{"kernel_confirm", vectorConfirmations, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &kernelConfirmCommand{}, flags...)
			c.deployer.now = vectorClock
			return c
		}, []string{"atlas"}, []string{"--amount", "2.71"}, nil},
		{"reader_grant", nil, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &readerGrantCommand{}, flags...)
			c.now = vectorClock
			return c
		}, []string{"atlas"}, nil, nil},
		// connect's first deploy: the material minted, the carried images
		// pushed, the load balancer's cost.
		{"connect_first", vectorFirstConnect, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, newConnectCommand(), flags...)
			vectorDeployer(&c.fatlineDeployer)
			c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
				return nil, errors.New("test: a plan dialled the carrier")
			}
			return c
		}, []string{"atlas"}, nil, vectorKey},
		// redeploy over the material the instance holds, replacing what an
		// earlier release deployed.
		{"redeploy", vectorRedeployed, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, newRedeployCommand(), flags...)
			vectorDeployer(&c.fatlineDeployer)
			return c
		}, []string{"atlas"}, []string{"--embedded"}, vectorMaterial},
		// build, its builder named: it reads the record alone.
		{"build", nil, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &buildCommand{}, flags...)
			c.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{} }
			c.newCluster = func(clusterRef) (jobWaiter, error) { return nil, errors.New("test: a plan opened the writer") }
			c.now = vectorClock
			return c
		}, []string{"atlas"}, []string{"--repo", "https://github.com/example/shop", "--app", "api", "--builder-image", builderDigest}, nil},
	}
}

// runPlanVector runs v, with extra flags, against a config directory that
// holds the vector's record and what its prepare writes, and nothing else,
// and returns what it printed in JSON mode, and its error.
func runPlanVector(t *testing.T, v planVector, extra ...string) (*Env, *bytes.Buffer, error) {
	t.Helper()
	dir := vectorConfigDir(t)
	meta := planVectorMeta()
	if v.edit != nil {
		v.edit(meta)
	}
	writeRecord(t, dir, meta)
	if v.prepare != nil {
		v.prepare(t, dir)
	}
	env, out := testEnv(dir, output.ModeJSON)
	err := v.cmd(t, append(append([]string(nil), v.flags...), extra...)...).Run(t.Context(), env, v.args)
	return env, out, err
}

func TestPlanVectors(t *testing.T) {
	usePlanVectorStamp(t)
	seen := map[string]bool{}
	for _, v := range planVectors() {
		t.Run(v.name, func(t *testing.T) {
			if seen[v.name] {
				t.Fatalf("two vectors are named %q", v.name)
			}
			seen[v.name] = true
			_, out, err := runPlanVector(t, v, "--plan")
			if err != nil {
				t.Fatal(err)
			}
			got := out.Bytes()
			doc := printedDocument(t, got)
			if b := decodedBound(t, doc); len(b.Blocked) != 0 || len(b.Facts) == 0 || b.Target.Project != "proj-atlas" {
				t.Fatalf("the vector is not a plan of the atlas fixture: %s", got)
			}
			// The same record, planned again, is the same bytes.
			if _, again, err := runPlanVector(t, v, "--plan"); err != nil || !bytes.Equal(got, again.Bytes()) {
				t.Fatalf("two plans from one record differ (%v):\n%s\n%s", err, got, again)
			}
			checkVector(t, "plan", v.name, got)
		})
	}
}

// TestPlanErrorVectors is the envelope --confirm prints for a plan that
// changed: kernel confirm, confirming the digest of no plan, printed as the
// router prints an error.
func TestPlanErrorVectors(t *testing.T) {
	usePlanVectorStamp(t)
	t.Run("plan_changed", func(t *testing.T) {
		var v planVector
		for _, pv := range planVectors() {
			if pv.name == "kernel_confirm" {
				v = pv
			}
		}
		env, out, err := runPlanVector(t, v, "--confirm", "sha256:"+strings.Repeat("0", 64))
		if kindOf(classified(err)) != kindPlanChanged || out.Len() != 0 {
			t.Fatalf("kernel confirm of another plan = %v, printing %q; want plan_changed", err, out)
		}
		env.Printer.PrintError(classified(err), exitCodeOf(err))
		checkVector(t, "plan", "error_plan_changed", out.Bytes())
	})
}
