package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
)

// The plan vectors (ADR 0023 M2.6, A23-29): each command's printed plan, byte
// for byte, made by the command itself through its seams against the atlas
// fixture's record, with this farcast's stamp and clock fixed at the world
// vectors' own. They read no cluster: the commands of M2.6a have plans that
// read none. They are produced in Go and are not copied to FarSightKit until
// ADR 0021 step 7.1. Each part of M2.6 adds the vectors of the commands it
// wires.
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
		}, []string{"atlas", "web"}, nil},
		{"kernel_confirm", vectorConfirmations, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &kernelConfirmCommand{}, flags...)
			c.deployer.now = vectorClock
			return c
		}, []string{"atlas"}, []string{"--amount", "2.71"}},
		{"reader_grant", nil, func(t *testing.T, flags ...string) Command {
			c := withFlags(t, &readerGrantCommand{}, flags...)
			c.now = vectorClock
			return c
		}, []string{"atlas"}, nil},
	}
}

// runPlanVector runs v, with extra flags, against a config directory that
// holds the vector's record and nothing else, and returns what it printed in
// JSON mode, and its error.
func runPlanVector(t *testing.T, v planVector, extra ...string) (*Env, *bytes.Buffer, error) {
	t.Helper()
	dir := vectorConfigDir(t)
	meta := planVectorMeta()
	if v.edit != nil {
		v.edit(meta)
	}
	writeRecord(t, dir, meta)
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
