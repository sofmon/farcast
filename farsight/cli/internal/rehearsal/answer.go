package rehearsal

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kernel"
	"github.com/sofmon/farcast/technocore/pricing"
)

// The reads 'farcast world' sends, as the in-process client sends them
// (ADR 0023 M2.4): each workload list is per kind, and every list carries
// limit (kube's page size).
const (
	pathWorkloads  = "/apis/apps/v1/namespaces/"
	pathNamespaces = "/api/v1/namespaces"
	pathConfigMaps = "/api/v1/namespaces/" + fldeploy.DefaultNamespace + "/configmaps/"
	// managedSelector is Planck's label on the namespaces it made, the one
	// world lists them by.
	managedSelector = "app.kubernetes.io/managed-by=farcast"
)

// read is one of world's reads, recognized.
type read struct {
	// resource is "deployments", "statefulsets", "namespaces" or
	// "configmaps".
	resource string
	// namespace is a workload list's; name a ConfigMap's.
	namespace, name string
}

// ClusterAnswer is the rehearsal's cluster: the API server's answer, status
// and body, to exactly the reads 'farcast world' sends as the reader —
//
//   - GET /apis/apps/v1/namespaces/{ns}/deployments and .../statefulsets,
//     whose query may hold limit and nothing else; each is a list of its own
//     kind, and its items carry no kind, as the API server's do not;
//   - GET /api/v1/namespaces, whose labelSelector must be exactly
//     app.kubernetes.io/managed-by=farcast, and which may hold limit;
//   - GET /api/v1/namespaces/farcast-system/configmaps/{name}, with no query:
//     a ConfigMap, or a 404 Kubernetes Status when the rehearsal holds none
//     by that name.
//
// The raw query is parsed, never compared as a string. Anything else — a
// write, a secret, another namespace's ConfigMap, a log, a list with continue
// or another key — is 405. A read of an expired rehearsal is a 500 Status
// carrying why, never a 503, which the client would retry. In unauthorized
// every read is 401, and in forbidden the kernel's checkpoint and the egress
// policy are 403, the metered-namespace list still answered, so apps reads.
//
// Which token asked is not its business: the handler refuses the writer's
// before it is asked. It is pure: the same spec, request and time give the
// same answer.
func ClusterAnswer(spec Spec, method, path, rawQuery string, now time.Time) (status int, body []byte) {
	r, ok := worldRead(method, path, rawQuery)
	if !ok {
		return http.StatusMethodNotAllowed, statusJSON(http.StatusMethodNotAllowed, "MethodNotAllowed",
			"the rehearsal's cluster answers only the reads 'farcast world' sends", nil)
	}
	if spec.expired(now) {
		return http.StatusInternalServerError, statusJSON(http.StatusInternalServerError, "InternalError", errExpired, nil)
	}
	if spec.Scenario == ScenarioUnauthorized {
		return http.StatusUnauthorized, statusJSON(http.StatusUnauthorized, "Unauthorized", "Unauthorized", nil)
	}
	switch r.resource {
	case "deployments":
		return http.StatusOK, marshal(workloadList(spec, r.namespace, "Deployment"))
	case "statefulsets":
		return http.StatusOK, marshal(workloadList(spec, r.namespace, "StatefulSet"))
	case "namespaces":
		return http.StatusOK, marshal(map[string]any{
			"apiVersion": "v1", "kind": "NamespaceList", "metadata": map[string]any{"resourceVersion": "1"},
			"items": []any{map[string]any{"metadata": map[string]any{
				"name": shopNamespace, "labels": map[string]any{"app.kubernetes.io/managed-by": "farcast"},
			}}},
		})
	}
	if spec.Scenario == ScenarioForbidden && (r.name == kernel.DefaultCheckpointName || r.name == fldeploy.PolicyConfigMap) {
		return http.StatusForbidden, statusJSON(http.StatusForbidden, "Forbidden", fmt.Sprintf(
			`configmaps %q is forbidden: User %q cannot get resource "configmaps" in API group "" in the namespace %q`,
			r.name, readerEmail(spec.Instance), fldeploy.DefaultNamespace),
			map[string]any{"name": r.name, "kind": "configmaps"})
	}
	return configMap(spec, r.name, now)
}

// worldRead recognizes one of world's reads (ClusterAnswer's list).
func worldRead(method, path, rawQuery string) (read, bool) {
	if method != http.MethodGet {
		return read{}, false
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return read{}, false
	}
	// only reports whether q holds no key but the ones allowed, each once.
	only := func(allowed ...string) bool {
		for k, v := range q {
			if !slices.Contains(allowed, k) || len(v) != 1 {
				return false
			}
		}
		return true
	}
	switch {
	case path == pathNamespaces:
		if sel, ok := q["labelSelector"]; !ok || len(sel) != 1 || sel[0] != managedSelector || !only("labelSelector", "limit") {
			return read{}, false
		}
		return read{resource: "namespaces"}, true
	case strings.HasPrefix(path, pathConfigMaps):
		name := strings.TrimPrefix(path, pathConfigMaps)
		if !plainName(name) || len(q) != 0 {
			return read{}, false
		}
		return read{resource: "configmaps", name: name}, true
	case strings.HasPrefix(path, pathWorkloads):
		ns, resource, ok := strings.Cut(strings.TrimPrefix(path, pathWorkloads), "/")
		if !ok || !plainName(ns) || (resource != "deployments" && resource != "statefulsets") || !only("limit") {
			return read{}, false
		}
		return read{resource: resource, namespace: ns}, true
	}
	return read{}, false
}

// plainName reports whether s is one path segment an object name can be:
// 1 to 253 of a-z, 0-9, '.' and '-', and never '.' or '..'.
func plainName(s string) bool {
	if s == "" || len(s) > 253 || s == "." || s == ".." {
		return false
	}
	return strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789.-") == ""
}

// statusJSON is a Failure Status, as the API server writes one.
func statusJSON(code int, reason, message string, details map[string]any) []byte {
	st := map[string]any{
		"kind": "Status", "apiVersion": "v1", "metadata": map[string]any{},
		"status": "Failure", "message": message, "reason": reason, "code": code,
	}
	if details != nil {
		st["details"] = details
	}
	return marshal(st)
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

// workloads is a namespace's Deployments and StatefulSets: the rehearsal's
// data, shaped by workloadList.
func workloads(spec Spec, namespace string) []workload {
	switch namespace {
	case fldeploy.DefaultNamespace:
		return []workload{
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
		return []workload{api, web}
	}
	return nil
}

// workloadList is a namespace's workloads of one kind, as the API server
// lists them: a <Kind>List whose items carry no kind. Any other namespace's
// list is empty.
func workloadList(spec Spec, namespace, kind string) map[string]any {
	items := []any{}
	for _, w := range workloads(spec, namespace) {
		if w.kind != kind {
			continue
		}
		containers := make([]any, 0, len(w.images))
		for i, img := range w.images {
			containers = append(containers, map[string]any{"name": fmt.Sprintf("%s-%d", w.name, i), "image": img})
		}
		items = append(items, map[string]any{
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
	return map[string]any{
		"apiVersion": "apps/v1", "kind": kind + "List", "metadata": map[string]any{"resourceVersion": "1"},
		"items": items,
	}
}

// configMap answers a ConfigMap read in farcast-system. A name the rehearsal
// does not hold is a 404 Status, which reads as absent.
func configMap(spec Spec, name string, now time.Time) (int, []byte) {
	unbuilt := func(what string, err error) (int, []byte) {
		return http.StatusInternalServerError, statusJSON(http.StatusInternalServerError, "InternalError",
			fmt.Sprintf("the rehearsal could not build its %s: %v", what, err), nil)
	}
	var key, value string
	switch name {
	case kernel.DefaultNamespacesName:
		b, err := json.Marshal(kernel.Namespaces{Version: kernel.NamespacesVersion, Meter: []string{fldeploy.DefaultNamespace, shopNamespace}})
		if err != nil {
			return unbuilt("metered-namespace list", err)
		}
		key, value = kernel.NamespacesKey(), string(b)
	case kernel.DefaultCheckpointName:
		cp, err := checkpoint(spec, now)
		if err != nil {
			return unbuilt("checkpoint", err)
		}
		key, value = kernel.CheckpointKey(), cp
	case fldeploy.PolicyConfigMap:
		doc := &policy.Document{Version: policy.Version, Apps: []policy.App{
			{Name: "api", Namespace: shopNamespace, CredentialSHA256: policy.HashCredential("rehearsal/shop/api"), External: declared()},
			{Name: "web", Namespace: shopNamespace, CredentialSHA256: policy.HashCredential("rehearsal/shop/web")},
		}}
		b, err := doc.Marshal()
		if err != nil {
			return unbuilt("egress policy", err)
		}
		key, value = fldeploy.PolicyKey, string(b)
	default:
		return http.StatusNotFound, statusJSON(http.StatusNotFound, "NotFound", fmt.Sprintf("configmaps %q not found", name),
			map[string]any{"name": name, "kind": "configmaps"})
	}
	return http.StatusOK, marshal(map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": name, "namespace": fldeploy.DefaultNamespace, "resourceVersion": "1"},
		"data":     map[string]any{key: value},
	})
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
// fresh, and it is refused once the period is over (ClusterAnswer refuses an
// expired rehearsal's every read first).
//
// The level is the kernel's own assessment of that ledger against the limit,
// never set by hand: a scenario at the limit is one whose ledger is over it.
// In cost-reached and at-floor, web's overrun is the sixteen hours before it
// was stopped. Read once the rehearsal has started, those begin more than
// four days into the period, after the confirmed window closed on the third,
// so the calibration stays one.
func checkpoint(spec Spec, now time.Time) (string, error) {
	if spec.expired(now) {
		return "", errors.New(errExpired)
	}
	start, end := spec.periodStart(), spec.periodEnd()
	ledger, err := cost.NewLedger(start, end)
	if err != nil {
		return "", err
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
		return "", err
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
		return "", err
	}
	return string(b), nil
}
