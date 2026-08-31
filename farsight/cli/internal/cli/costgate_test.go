package cli

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/technocore/pricing"
)

// renderedRequests reads the CPU and memory a rendered manifest actually asks
// for. The point of parsing the YAML rather than reading the constants is that
// the constants are what the estimate is computed from — checking them against
// themselves would prove nothing.
func renderedRequests(t *testing.T, manifest []byte) (cpuMilli, memMiB int) {
	t.Helper()
	s := string(manifest)
	cpu := regexp.MustCompile(`cpu: (\d+)m`).FindStringSubmatch(s)
	mem := regexp.MustCompile(`memory: (\d+)Mi`).FindStringSubmatch(s)
	if cpu == nil || mem == nil {
		t.Fatalf("rendered manifest declares no cpu/memory requests")
	}
	c, err := strconv.Atoi(cpu[1])
	if err != nil {
		t.Fatal(err)
	}
	m, err := strconv.Atoi(mem[1])
	if err != nil {
		t.Fatal(err)
	}
	return c, m
}

func dollarsIn(t *testing.T, s string) []float64 {
	t.Helper()
	var out []float64
	for _, m := range regexp.MustCompile(`\$(\d+(?:\.\d+)?)`).FindAllStringSubmatch(s, -1) {
		v, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// Cost control is the second pillar and nothing tested the number the operator
// is actually shown. It was wrong: the keyholder gate quoted ~$4/month for two
// replicas that cost ~$7.39, because the constant was ADR 0008's MARGINAL
// second-replica figure copied as the cost of the pair.
//
// The property here is end to end on purpose — the figure in the prompt must
// price the workload that gets applied, computed from the requests parsed back
// out of the rendered manifest. A drift in either the manifest or the estimate
// breaks it.
func TestKeyholderCostGateQuotesThePriceOfTheWorkloadItDeploys(t *testing.T) {
	manifests, err := dsdeploy.Render(dsdeploy.Config{
		Image:         "example/datasphered@sha256:" + strings.Repeat("a", 64),
		Replicas:      keyholderReplicas,
		Instance:      "p41",
		Bucket:        "b",
		Provider:      "gcs",
		Project:       "proj-1",
		Location:      "us-central1",
		CACertPEM:     []byte("CA"),
		ServerCertPEM: []byte("CRT"),
		ServerKeyPEM:  []byte("KEY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	cpu, mem := renderedRequests(t, manifests)
	want := pricing.WorkloadMonthlyUSD(keyholderReplicas, cpu, mem)

	if math.Abs(keyholderMonthlyUSD-want) > 0.01 {
		t.Fatalf("gate quotes $%.2f/month but the applied workload costs $%.2f/month", keyholderMonthlyUSD, want)
	}
	// The specific regression: the pair must not be quoted at the price of
	// one more replica.
	if math.Abs(keyholderMonthlyUSD-pricing.MarginalReplicaMonthlyUSD(cpu, mem)) < 0.01 {
		t.Error("the gate is quoting the marginal replica cost as the cost of the fleet")
	}
}

// The non-interactive branch is the one automation sees, and it must carry the
// same figure rather than a rounded-down convenience.
func TestKeyholderCostGateRefusesNonInteractivelyWithTheFigure(t *testing.T) {
	dir := config.Dir(t.TempDir())
	env, _ := testEnv(dir, output.ModeHuman)
	c := &storageDeployCommand{}
	meta := &config.InstanceMetadata{
		Name:      "p41",
		CostLimit: config.CostLimit{Amount: 50, Currency: "USD", Period: "monthly"},
	}
	ok, err := c.confirmCost(env, meta)
	if ok || err == nil {
		t.Fatalf("expected a refusal without --yes; got ok=%v err=%v", ok, err)
	}
	got := dollarsIn(t, err.Error())
	if len(got) == 0 {
		t.Fatalf("refusal names no figure: %v", err)
	}
	if math.Abs(got[0]-math.Round(keyholderMonthlyUSD)) > 0.51 {
		t.Errorf("refusal quotes $%.2f, want ~$%.2f", got[0], keyholderMonthlyUSD)
	}
}

// FatLine's second replica is bought by ADR 0009 decision 11 at the same
// marginal price as datasphered's. If someone reverts the replica count, this
// says so in money rather than in YAML.
func TestFatLineSecondReplicaCostsWhatTheADRClaims(t *testing.T) {
	manifests, err := fldeploy.Render(fldeploy.Config{
		Image:         "example/fatline:test",
		CACertPEM:     []byte("CA"),
		ServerCertPEM: []byte("CRT"),
		ServerKeyPEM:  []byte("KEY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	cpu, mem := renderedRequests(t, manifests)
	marginal := pricing.MarginalReplicaMonthlyUSD(cpu, mem)
	if marginal < 3 || marginal > 5 {
		t.Errorf("the marginal FatLine replica costs $%.2f/month; ADR 0009 decision 11 claims ~$4", marginal)
	}
	if !strings.Contains(string(manifests), fmt.Sprintf("replicas: %d", fldeploy.DefaultReplicas)) {
		t.Error("the rendered Deployment does not carry the default replica count")
	}
}

// Connect creates two standing costs, not one: the carrier and FatLine's own
// replicas. Quoting only the carrier is the same class of error the keyholder
// gate had — a true number that is not the whole number — and ADR 0009
// decision 11 doubled the half that was missing.
func TestConnectCostGateNamesFatLineAsWellAsTheCarrier(t *testing.T) {
	want := pricing.WorkloadMonthlyUSD(fldeploy.DefaultReplicas, fldeploy.RequestCPUMilli, fldeploy.RequestMemMiB)
	if math.Abs(fatlineMonthlyUSD-want) > 0.01 {
		t.Fatalf("connect prices FatLine at $%.2f/month; its manifest costs $%.2f/month", fatlineMonthlyUSD, want)
	}

	dir := config.Dir(t.TempDir())
	env, _ := testEnv(dir, output.ModeHuman)
	c := &connectCommand{}
	meta := &config.InstanceMetadata{
		Name:      "p41",
		CostLimit: config.CostLimit{Amount: 50, Currency: "USD", Period: "monthly"},
	}
	ok, err := c.confirmCost(env, meta)
	if ok || err == nil {
		t.Fatalf("expected a refusal without --yes; got ok=%v err=%v", ok, err)
	}
	got := dollarsIn(t, err.Error())
	if len(got) < 2 {
		t.Fatalf("refusal names %d figures, want the carrier and FatLine: %v", len(got), err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "fatline") {
		t.Errorf("refusal does not name FatLine's standing cost: %v", err)
	}
}
