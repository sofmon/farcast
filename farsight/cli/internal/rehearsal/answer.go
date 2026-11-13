package rehearsal

import (
	"encoding/json"
	"slices"
	"time"

	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kernel"
	"github.com/sofmon/farcast/technocore/pricing"
)

// ClusterAnswer is the rehearsal's cluster: the stdout kubectl would print for
// exactly the reads 'farcast world' sends (the shapes cluster.go builds), args
// being everything after --kubeconfig <path>. Anything else — a write, a
// secret, -A, another shape — is not answered, and ok is false. It is pure:
// the same spec, args and time give the same bytes.
func ClusterAnswer(spec Spec, args []string, now time.Time) (stdout []byte, ok bool) {
	system := fldeploy.DefaultNamespace
	switch {
	case len(args) == 6 && args[0] == "get" && args[1] == "deployments,statefulsets" && args[2] == "-n" &&
		args[4] == "-o" && args[5] == "json":
		return marshal(workloads(spec, args[3])), true
	case slices.Equal(args, []string{"get", "namespace", "-l", "app.kubernetes.io/managed-by=farcast", "-o", "json"}):
		return marshal(map[string]any{"items": []any{map[string]any{"metadata": map[string]any{"name": shopNamespace}}}}), true
	case len(args) == 8 && args[0] == "get" && args[1] == "configmap" && args[3] == "-n" && args[4] == system &&
		args[5] == "--ignore-not-found" && args[6] == "-o" && args[7] == "json":
		return configMap(spec, args[2], now)
	}
	return nil, false
}

func marshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// Every value here is built from maps, slices and strings.
		panic(err)
	}
	return append(b, '\n')
}

type workload struct {
	kind, name string
	desired    int
	ready      int
	images     []string
}

// workloads is a namespace's Deployments and StatefulSets, shaped as
// cluster.Workloads reads them.
func workloads(spec Spec, namespace string) map[string]any {
	var ws []workload
	switch namespace {
	case fldeploy.DefaultNamespace:
		ws = []workload{
			{"Deployment", nameFatLine, 1, 1, []string{spec.Images[nameFatLine], spec.Images[nameShrike]}},
			{"Deployment", nameKernel, 1, 1, []string{spec.Images[nameKernel]}},
			{"StatefulSet", nameKeyholder, 2, 2, []string{spec.Images[nameKeyholder]}},
		}
	case shopNamespace:
		api := workload{"Deployment", "api", 2, 2, []string{imageRef("shop-api")}}
		web := workload{"Deployment", "web", 1, 1, []string{imageRef("shop-web")}}
		switch spec.Scenario {
		case ScenarioCostReached:
			// What a protective cost shutdown leaves: scaled to zero.
			web.desired, web.ready = 0, 0
		case ScenarioAtFloor:
			// Every application stopped: nothing left for a shutdown.
			api.desired, api.ready = 0, 0
			web.desired, web.ready = 0, 0
		}
		ws = []workload{api, web}
	}
	items := make([]any, 0, len(ws))
	for _, w := range ws {
		containers := make([]any, 0, len(w.images))
		for _, img := range w.images {
			containers = append(containers, map[string]any{"image": img})
		}
		items = append(items, map[string]any{
			"kind": w.kind,
			"metadata": map[string]any{
				"name": w.name, "namespace": namespace,
				"labels":            map[string]any{"app.kubernetes.io/managed-by": "farcast"},
				"creationTimestamp": spec.Started.UTC().Format(time.RFC3339),
			},
			"spec": map[string]any{
				"replicas": w.desired,
				"template": map[string]any{"spec": map[string]any{"containers": containers}},
			},
			"status": map[string]any{"readyReplicas": w.ready},
		})
	}
	return map[string]any{"items": items}
}

// configMap answers a ConfigMap read in farcast-system. A name the rehearsal
// does not hold is empty stdout, which reads as not found.
func configMap(spec Spec, name string, now time.Time) ([]byte, bool) {
	var key, value string
	switch name {
	case kernel.DefaultNamespacesName:
		b, err := json.Marshal(kernel.Namespaces{Version: kernel.NamespacesVersion, Meter: []string{fldeploy.DefaultNamespace, shopNamespace}})
		if err != nil {
			return nil, false
		}
		key, value = kernel.NamespacesKey(), string(b)
	case kernel.DefaultCheckpointName:
		cp, ok := checkpoint(spec, now)
		if !ok {
			return nil, false
		}
		key, value = kernel.CheckpointKey(), cp
	case fldeploy.PolicyConfigMap:
		doc := &policy.Document{Version: policy.Version, Apps: []policy.App{
			{Name: "api", Namespace: shopNamespace, CredentialSHA256: policy.HashCredential("rehearsal/shop/api"), External: declared()},
			{Name: "web", Namespace: shopNamespace, CredentialSHA256: policy.HashCredential("rehearsal/shop/web")},
		}}
		b, err := doc.Marshal()
		if err != nil {
			return nil, false
		}
		key, value = fldeploy.PolicyKey, string(b)
	default:
		return nil, true
	}
	return marshal(map[string]any{
		"metadata": map[string]any{"name": name, "namespace": fldeploy.DefaultNamespace, "resourceVersion": "1"},
		"data":     map[string]any{key: value},
	}), true
}

// appRates are what the ledger accrues, per application, in USD an hour:
// binary fractions, so every figure the ledger holds is exact. Keyed as the
// kernel keys them, by namespace and name.
var appRates = []struct {
	ns, app string
	usd     float64
}{
	{shopNamespace, "api", 1.0 / 64}, {shopNamespace, "web", 1.0 / 128}, {fldeploy.DefaultNamespace, nameKernel, 1.0 / 256},
	{fldeploy.DefaultNamespace, nameFatLine, 1.0 / 512}, {fldeploy.DefaultNamespace, nameKeyholder, 1.0 / 1024},
}

// limitUSD is the monthly cost limit: the one the rehearsal's record holds,
// and the one its kernel enforces.
const limitUSD float64 = 50

// overrunHours is how long web ran hot before it was stopped, in the
// scenarios at the limit. Its burn over them is the whole limit, so spending
// stands over the limit as it does for a real kernel that has reached it —
// never a level flipped beside a total of a few percent (phase 7, F6).
const overrunHours = 16

// overruns reports whether the scenario's kernel has reached its limit.
func overruns(spec Spec) bool {
	return spec.Scenario == ScenarioCostReached || spec.Scenario == ScenarioAtFloor
}

// checkpoint is the kernel's checkpoint as of now: a ledger whose period
// starts at UTC midnight five days before the rehearsal did, accrued to now,
// with one confirmed window — two days, closed, inside the period and before
// the rehearsal started — that matches the model exactly, so the calibration
// is one. Spending reads split, confirmed and expected, on any day of a
// calendar month. It is computed on every read, so a long rehearsal stays
// fresh, and it is refused once the period is over.
//
// The level is the kernel's own assessment of that ledger against the limit,
// never set by hand: a scenario at the limit is one whose ledger is over it.
// In cost-reached and at-floor, web's overrun is the sixteen hours before it
// was stopped. Read once the rehearsal has started, those begin more than
// four days into the period, after the confirmed window closed on the third,
// so the calibration stays one.
func checkpoint(spec Spec, now time.Time) (string, bool) {
	if spec.expired(now) {
		return "", false
	}
	start, end := spec.periodStart(), spec.periodEnd()
	ledger, err := cost.NewLedger(start, end)
	if err != nil {
		return "", false
	}
	observed := now.Add(-2 * time.Minute)
	if spec.Scenario == ScenarioStaleCheckpoint {
		observed = now.Add(-30 * time.Minute)
	}
	stopped := observed.Add(-50 * time.Minute).UTC()
	var hourly float64
	for _, r := range appRates {
		ledger.Accrue(now, kernel.AppKey(r.ns, r.app), r.usd, now.Sub(start))
		hourly += r.usd
	}
	if overruns(spec) {
		ledger.Accrue(stopped, kernel.AppKey(shopNamespace, "web"), limitUSD/overrunHours, overrunHours*time.Hour)
	}
	if _, err := ledger.Confirm(cost.Confirmation{
		Start: start.Add(24 * time.Hour), End: start.Add(3 * 24 * time.Hour),
		USD: hourly * 48, AsOf: start.Add(4 * 24 * time.Hour),
	}); err != nil {
		return "", false
	}
	level := cost.Assess(ledger.Accrued().Total, limitUSD, hourly, now, end).Level.String()
	cp := kernel.Checkpoint{
		Version: kernel.CheckpointVersion,
		Ledger:  ledger.Snapshot(),
		Last:    observed.UTC(),
		Observed: kernel.Observation{
			At: observed.UTC(), Pods: 7, RateHourlyUSD: hourly,
			Carrier: string(kernel.CarrierLoadBalancer), Level: level, Limit: limitUSD,
		},
	}
	// cost-reached is a kernel that recorded no stop: web is at zero, and
	// why is not said. at-floor is one that stopped both applications,
	// recorded it, and found nothing left to stop.
	if spec.Scenario == ScenarioAtFloor {
		burning := pricing.CarrierHourlyUSD
		for _, r := range appRates {
			if r.ns == shopNamespace {
				// What stopping saved: web ran hot right up to its stop.
				saved := r.usd
				if r.app == "web" {
					saved += limitUSD / overrunHours
				}
				cp.Stops = append(cp.Stops, kernel.Stop{Namespace: r.ns, Deployment: r.app, At: stopped,
					Reason: kernel.StopReasonCostGuard, HourlyUSD: saved})
			} else {
				burning += r.usd
			}
		}
		cp.Floor = &kernel.Floor{Since: observed.Add(-49 * time.Minute).UTC(), HourlyUSD: burning,
			Levers: []string{kernel.LeverCarrier, kernel.LeverRelease}}
	}
	b, err := json.Marshal(cp)
	if err != nil {
		return "", false
	}
	return string(b), true
}
