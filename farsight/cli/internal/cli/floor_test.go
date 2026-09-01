package cli

import (
	"bytes"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
)

func TestFloorNowCountsOnlyWhatIsDeployed(t *testing.T) {
	fresh := floorNow(&config.InstanceMetadata{})
	if len(fresh.Items) != 1 || fresh.Items[0].Name != "cluster" {
		t.Fatalf("a freshly installed instance's floor is %v, want just the cluster", fresh.Items)
	}
	if fresh.Total != emptyClusterMonthlyUSD {
		t.Errorf("total = %.2f, want %d", fresh.Total, emptyClusterMonthlyUSD)
	}

	// 192.0.2.0/24 is TEST-NET-1, reserved for documentation. A plausible
	// real address in a fixture is one a secret scan has to be taught to
	// ignore, and a scan with a standing exception is one nobody reads.
	full := &config.InstanceMetadata{
		FatLineDeployed: true,
		Carrier:         &config.Carrier{Endpoint: "192.0.2.10:8443"},
		Keyholder:       &config.Keyholder{Deployed: true},
		Kernel:          &config.Kernel{Deployed: true},
	}
	got := floorNow(full)
	if len(got.Items) != 5 {
		t.Fatalf("a fully provisioned instance has %d floor items, want 5: %v", len(got.Items), got.Items)
	}
	if got.Total <= fresh.Total {
		t.Errorf("a provisioned instance (%.2f) must cost more than an empty one (%.2f)", got.Total, fresh.Total)
	}
	// floorNow on a fully provisioned instance is floorFull.
	if math.Abs(got.Total-floorFull(full).Total) > 0.01 {
		t.Errorf("floorNow=%.2f floorFull=%.2f; they must agree once everything is deployed", got.Total, floorFull(full).Total)
	}
}

// The check that matters is against the FULLY PROVISIONED floor. An instance
// installed today runs almost nothing, so checking a limit against what is
// deployed at that moment would pass a figure the operator is guaranteed to
// breach two commands later.
func TestFloorFullIgnoresWhatIsDeployedYet(t *testing.T) {
	empty := floorFull(&config.InstanceMetadata{})
	provisioned := floorFull(&config.InstanceMetadata{
		FatLineDeployed: true,
		Carrier:         &config.Carrier{Endpoint: "192.0.2.10:8443"},
		Keyholder:       &config.Keyholder{Deployed: true},
		Kernel:          &config.Kernel{Deployed: true},
	})
	if math.Abs(empty.Total-provisioned.Total) > 0.01 {
		t.Errorf("floorFull changed with deployment state: %.2f vs %.2f", empty.Total, provisioned.Total)
	}
	if len(empty.Items) != 5 {
		t.Errorf("floorFull has %d items, want 5", len(empty.Items))
	}
}

// ADR 0009's own arithmetic: about $37 cluster + $18 carrier + the system
// tier. If this moves, a documented figure moved with it.
func TestTheFullFloorIsAboutSeventyThreeDollars(t *testing.T) {
	got := floorFull(&config.InstanceMetadata{}).Total
	if got < 65 || got > 85 {
		t.Errorf("the fully provisioned floor is $%.2f/mo; ADR 0009 says roughly $73", got)
	}
}

// Every line is derived from the manifests' own declared requests, so the
// number an operator is shown cannot drift from the workloads applied.
func TestTheKernelLineMatchesItsManifest(t *testing.T) {
	var kernel float64
	for _, it := range floorFull(&config.InstanceMetadata{}).Items {
		if it.Name == "technocore" {
			kernel = it.MonthlyUSD
		}
	}
	if math.Abs(kernel-kernelMonthlyUSD) > 0.01 {
		t.Errorf("floor prices the kernel at %.4f, the gate at %.4f", kernel, kernelMonthlyUSD)
	}
	if tcdeploy.Replicas != 1 {
		t.Errorf("the floor assumes one kernel replica, the manifest renders %d", tcdeploy.Replicas)
	}
}

func TestWarnIfBelowFloorSaysWhatCannotBeMet(t *testing.T) {
	var buf bytes.Buffer
	limit := config.CostLimit{Amount: 50, Currency: "USD", Period: "monthly"}
	below := warnIfBelowFloor(&buf, limit, floorFull(&config.InstanceMetadata{}), "a fully provisioned instance")
	if !below {
		t.Fatal("USD 50 is below the ~$73 floor and must be reported as such")
	}
	out := buf.String()
	for _, want := range []string{"below what", "limit", "cluster", "carrier", "total", "estimates"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning does not mention %q:\n%s", want, out)
		}
	}
	// It must say WHY the kernel cannot fix it, or the operator will assume
	// the shutdown will handle it.
	if !strings.Contains(out, "never stops the tunnel") {
		t.Error("the warning does not explain that a shutdown cannot reach the floor")
	}
}

func TestWarnIfBelowFloorIsSilentWhenTheLimitClearsIt(t *testing.T) {
	var buf bytes.Buffer
	limit := config.CostLimit{Amount: 500, Currency: "USD", Period: "monthly"}
	if warnIfBelowFloor(&buf, limit, floorFull(&config.InstanceMetadata{}), "x") {
		t.Error("a limit above the floor must not warn")
	}
	if buf.Len() != 0 {
		t.Errorf("wrote %q for a limit that clears the floor", buf.String())
	}
}

// A missing limit is install's problem, not the floor check's. Warning here
// would report a configuration error as a cost problem.
func TestWarnIfBelowFloorIgnoresAnAbsentLimit(t *testing.T) {
	var buf bytes.Buffer
	for _, amount := range []float64{0, -1} {
		if warnIfBelowFloor(&buf, config.CostLimit{Amount: amount, Currency: "USD"}, floorFull(&config.InstanceMetadata{}), "x") {
			t.Errorf("limit %v produced a floor warning", amount)
		}
	}
}

// Found by the 2026-09-01 runbook walk: the floor check was inside
// printSummary, which runs only when a human is being prompted. An unattended
// `install --yes` — the exact place a limit that cannot be met would sit
// unnoticed for months — never saw it.
//
// The earlier tests covered the function and not its placement, which is how a
// correct function ends up on a path nobody takes.
func TestTheFloorCheckRunsOnTheUnattendedInstallPath(t *testing.T) {
	src, err := os.ReadFile("install.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	call := strings.Index(body, "warnIfBelowFloor(")
	if call < 0 {
		t.Fatal("install.go no longer performs a floor check at all")
	}
	gate := strings.Index(body, "if !c.assumeYes {")
	if gate < 0 {
		t.Fatal("install.go no longer has a confirmation gate")
	}
	if call > gate {
		t.Error("the floor check happens after the --yes gate; an unattended install would skip it")
	}
	if strings.Contains(body[strings.Index(body, "func (c *installCommand) printSummary"):], "warnIfBelowFloor(") {
		t.Error("the floor check is back inside printSummary, which only runs when a human is prompted")
	}
}
