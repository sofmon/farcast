package rehearsal

import (
	"encoding/json"
	"slices"
	"time"

	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kernel"
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
		web := workload{"Deployment", "web", 1, 1, []string{imageRef("shop-web")}}
		if spec.Scenario == ScenarioCostReached {
			// What a protective cost shutdown leaves: scaled to zero.
			web.desired, web.ready = 0, 0
		}
		ws = []workload{{"Deployment", "api", 2, 2, []string{imageRef("shop-api")}}, web}
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
// binary fractions, so every figure the ledger holds is exact.
var appRates = []struct {
	app string
	usd float64
}{
	{"api", 1.0 / 64}, {"web", 1.0 / 128}, {nameKernel, 1.0 / 256}, {nameFatLine, 1.0 / 512}, {nameKeyholder, 1.0 / 1024},
}

// checkpoint is the kernel's checkpoint as of now: a ledger whose period
// starts at UTC midnight five days before the rehearsal did, accrued to now,
// with one confirmed window — two days, closed, inside the period and before
// the rehearsal started — that matches the model exactly, so the calibration
// is one. Spending reads split, confirmed and expected, on any day of a
// calendar month. It is computed on every read, so a long rehearsal stays
// fresh, and it is refused once the period is over.
func checkpoint(spec Spec, now time.Time) (string, bool) {
	if spec.expired(now) {
		return "", false
	}
	start, end := spec.periodStart(), spec.periodEnd()
	ledger, err := cost.NewLedger(start, end)
	if err != nil {
		return "", false
	}
	var hourly float64
	for _, r := range appRates {
		ledger.Accrue(now, r.app, r.usd, now.Sub(start))
		hourly += r.usd
	}
	if _, err := ledger.Confirm(cost.Confirmation{
		Start: start.Add(24 * time.Hour), End: start.Add(3 * 24 * time.Hour),
		USD: hourly * 48, AsOf: start.Add(4 * 24 * time.Hour),
	}); err != nil {
		return "", false
	}
	observed := now.Add(-2 * time.Minute)
	if spec.Scenario == ScenarioStaleCheckpoint {
		observed = now.Add(-30 * time.Minute)
	}
	level := cost.LevelOK.String()
	if spec.Scenario == ScenarioCostReached {
		level = cost.LevelReached.String()
	}
	b, err := json.Marshal(kernel.Checkpoint{
		Version: kernel.CheckpointVersion,
		Ledger:  ledger.Snapshot(),
		Last:    observed.UTC(),
		Observed: kernel.Observation{
			At: observed.UTC(), Pods: 7, RateHourlyUSD: hourly,
			Carrier: string(kernel.CarrierLoadBalancer), Level: level, Limit: 50,
		},
	})
	if err != nil {
		return "", false
	}
	return string(b), true
}
