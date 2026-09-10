# Phase 5.3 — Live Validation

**Status: written, not yet walked.**

Phase 5.3 gives an application two things it has been compiling against since 0.2: configuration it can read, and secrets an operator provisions. The unit suite proves the refusals bite under mutation — 24 mutations, every one caught — and the cross-module tests prove the CLI writes the key Planck tells the application to read. What none of that proves is that a real application in a real cluster, handed a real ConfigMap, reads a real secret out of a real keyholder.

Designed by [ADR 0017](../adr/0017-application-secrets.md), on the keyholder [ADR 0008](../adr/0008-in-cluster-key-delivery.md) built.

---

## Prerequisites

An instance installed, connected, toolchain mirrored, kernel deployed, and a keyholder deployed and unsealed — the state [the 3.2 runbook](phase-3-2-validation.md) leaves behind. The builder's push grant applied **before** the first build ([the 4.2 runbook](phase-4-2-validation.md), and the 5.1b walk that proved what happens otherwise).

The application needs to do one thing this repository's sample applications do not yet do: call `farcast.Config()` and `farcast.Secrets()` and report what it got. Build a small one against `github.com/sofmon/farcast/sdk/go` that exposes an endpoint printing the *presence* — never the value — of each.

---

## 1. Does a secret written here reach an application there?

```bash
printf '%s' 'hunter2' | farcast secret set "$INSTANCE" api DB_PASSWORD
farcast secret ls "$INSTANCE"
farcast run "$INSTANCE" "$REPO"
farcast logs "$INSTANCE" api | grep secret
```

**Expect:** `secret ls` lists `api DB_PASSWORD` and no value. The application reports the secret present and the right length. The pod's ConfigMap carries `FARCAST_SECRETS_PREFIX: app/secrets/api/` and no secret value.

This is the criterion the whole phase turns on: the operator's key and the application's key are computed in different packages from different inputs, and a divergence stores a secret nothing ever fetches.

## 2. Is the object in the bucket actually opaque?

```bash
gcloud storage ls "gs://$BUCKET" --credentials "$KEYFILE" | head
gcloud storage cat "gs://$BUCKET/<stored-name>" --credentials "$KEYFILE" | xxd | head
```

**Expect:** no object name contains `secrets`, `api` or `DB_PASSWORD`, and no object's bytes contain `hunter2`.

## 3. Does the cluster hold the secret anywhere?

```bash
kubectl -n "$APPS" get secret
kubectl -n "$APPS" get configmap api -o yaml
kubectl -n "$APPS" get secret api-egress -o jsonpath='{.data}' | base64 -d
```

**Expect:** the only Secret is `api-egress` (the egress credential, [ADR 0013](../adr/0013-per-application-egress-identity.md)), and `hunter2` appears in neither it nor the ConfigMap. This is the phase's stated prohibition — *never in plaintext in K8s* — checked against the cluster rather than against the template.

## 4. Does the keyholder refuse an application that writes a secret?

From inside the application's pod, against the keyholder's data path:

```bash
kubectl -n "$APPS" exec deploy/api -- sh -c \
  'curl -sS -o /dev/null -w "%{http_code} %{header_json}" -X PUT \
   --cacert /ca.pem -H "X-Farcast-Scope: app" \
   -H "X-Farcast-Key: $(printf app/secrets/api/PLANTED | base64)" \
   --data planted "$FARCAST_STORAGE_ENDPOINT/v1/object"'
```

**Expect:** `403` with `X-Farcast-Code: permission`, and `farcast secret ls` still showing only `DB_PASSWORD`. Repeat with `DELETE` on the existing secret and confirm it survives.

**Also expect — and this is the uncomfortable half — a `GET` of another application's secret to SUCCEED.** Deploy a second application, give it a secret, and read it from the first. [ADR 0017](../adr/0017-application-secrets.md) decision 2 says the boundary is the instance and not the application; the walk should demonstrate it rather than take the ADR's word, because an operator who assumed otherwise would put a payment credential behind it.

## 5. Does a sealed instance stop secrets, and say so?

```bash
farcast storage seal "$INSTANCE"
farcast logs "$INSTANCE" api --follow
```

**Expect:** the application reports the seal — `ErrStorageSealed`, not "no such secret" — and recovers on `farcast storage unseal` without a restart. An application that read a seal as absence and started over would be silent data loss by a second route.

## 6. Does `Config()` refuse the platform's namespace in a real pod?

**Expect:** the application's own variables read back correctly, `Config().Get("FARCAST_FATLINE_PROXY")` reports absent, `Require` on it reports `ErrConfigReserved`, and `farcast.AppName()` returns the manifest's name. The credential is present in the environment throughout — this is the check that the refusal is doing work where it matters, not just in a unit test.

## 7. Does the redaction hold on the wire?

Have the application log the `Secret` directly, marshal a struct containing one, and format it with `%v` and `%#v`.

**Expect:** `[redacted]` in `farcast logs` every time, a marshalling error rather than a document, and `hunter2` nowhere in the log stream.

## 8. Rotation and removal

```bash
printf '%s' 'hunter3' | farcast secret set "$INSTANCE" api DB_PASSWORD --force
kubectl -n "$APPS" rollout restart deploy/api
farcast secret rm "$INSTANCE" api DB_PASSWORD -y
```

**Expect:** the application reads the new value after the restart (there is no cache, so a fresh `Get` should see it even without one — confirm which), and after `rm` reports `ErrSecretNotFound` rather than the stale value.

---

## Criteria

1. A secret set from the operator's machine is read by the application, by name, first try.
2. The bucket object's name and bytes disclose neither the name nor the value.
3. No Kubernetes Secret or ConfigMap anywhere holds the value.
4. An application's `PUT` and `DELETE` under `secrets/` are refused with `permission`.
5. An application's `GET` of a **neighbour's** secret succeeds, matching what ADR 0017 states rather than what the name suggests.
6. A seal reports as a seal, and clears without a restart.
7. `Config()` refuses `FARCAST_*` in a pod that genuinely has those variables set.
8. A `Secret` reaches no log, no error and no marshalled document in the clear.
9. `--force` rotates, `rm` removes, and the application sees both.
10. Teardown leaves no billable resource — verified independently, not from local state.
