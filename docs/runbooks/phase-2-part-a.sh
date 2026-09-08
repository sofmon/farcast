#!/usr/bin/env bash
#
# Phase 2 — Part A (local, free) validation, automated.
#
# Runs every operation from "Part A" of docs/runbooks/phase-2-validation.md and
# STOPS and PRINTS on the first error (failed command OR failed assertion):
#
#   A0  guardrails (go test -race / vet / gofmt / golangci-lint) + build to ./bin
#   A1  FatLine egress + Shrike sidecar over loopback, with assertions on the
#       live Shrike security picture (declared host, warning×3, cleartext info,
#       allowed host) and the alert log
#   A2  the tunnel / per-instance-CA / identity tests (mTLS handshake, SAN)
#   A3  `farcast connect` no-cloud surface (exit codes 2 / 2 / 1)
#
# Safe: NO cloud, NO cost. It builds binaries into ./bin and runs two loopback
# servers on 127.0.0.1:18131 (FatLine egress) and 127.0.0.1:18132 (Shrike status),
# which are torn down on exit. macOS-friendly (works on the stock bash 3.2).
#
# Usage:  bash docs/runbooks/phase-2-part-a.sh

set -euo pipefail

# ---- output helpers --------------------------------------------------------
if [ -t 1 ]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  BOLD=''; RED=''; GRN=''; DIM=''; RST=''
fi
STEP="(startup)"
step() { STEP="$1"; printf '\n%s==> %s%s\n' "$BOLD" "$1" "$RST"; }
ok()   { printf '%s  ✓ %s%s\n' "$GRN" "$1" "$RST"; }
note() { printf '%s    %s%s\n' "$DIM" "$1" "$RST"; }
die()  { printf '\n%s  ✗ %s%s\n' "$RED$BOLD" "$1" "$RST" >&2; exit 1; }

# ---- config ----------------------------------------------------------------
EGRESS_PORT=18131
STATUS_PORT=18132
SHRIKE_PID=''
FATLINE_PID=''
TMP=''

cleanup() {
  [ -n "$FATLINE_PID" ] && kill "$FATLINE_PID" 2>/dev/null || true
  [ -n "$SHRIKE_PID" ]  && kill "$SHRIKE_PID"  2>/dev/null || true
  wait 2>/dev/null || true
  [ -n "$TMP" ] && rm -rf "$TMP" || true
}
on_err() {
  local rc=$?
  printf '\n%s✗ FAILED during: %s%s\n' "$RED$BOLD" "$STEP" "$RST" >&2
  printf '%s  exit %d at line %s — last command: %s%s\n' \
    "$RED" "$rc" "${1:-?}" "${BASH_COMMAND:-?}" "$RST" >&2
}
trap 'on_err $LINENO' ERR
trap cleanup EXIT

# ---- small utilities -------------------------------------------------------
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }   # 0 = something is listening
wait_port() { local p=$1 s=${2:-5} i=0; while [ "$i" -lt "$((s * 10))" ]; do port_open "$p" && return 0; sleep 0.1; i=$((i + 1)); done; return 1; }
wait_http() { local u=$1 s=${2:-5} i=0; while [ "$i" -lt "$((s * 10))" ]; do curl -fsS -o /dev/null "$u" 2>/dev/null && return 0; sleep 0.1; i=$((i + 1)); done; return 1; }
expect_exit() {            # want, label, cmd...
  local want=$1 label=$2; shift 2
  local rc=0; "$@" >/dev/null 2>&1 || rc=$?
  if [ "$rc" = "$want" ]; then ok "$label → exit $rc"; else die "$label → exit $rc, want $want"; fi
}

sha256_hex() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 | cut -d' ' -f1
  else sha256sum | cut -d' ' -f1
  fi
}

# ---- locate repo root ------------------------------------------------------
step "Locating the repository root"
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && git rev-parse --show-toplevel) || die "not inside the farcast git checkout"
cd "$ROOT"
ok "repo root: $ROOT"

# ---- preflight -------------------------------------------------------------
step "Preflight — required tools"
command -v go   >/dev/null || die "go is not on PATH"
command -v curl >/dev/null || die "curl is not on PATH"
ok "go $(go version | awk '{print $3}'); curl present"
HAVE_PY=0
if command -v python3 >/dev/null; then HAVE_PY=1; ok "python3 present (precise JSON assertions)"; else note "python3 absent — JSON assertions fall back to grep"; fi

# ---- A0 — guardrails & build ----------------------------------------------
step "A0 — guardrails (test -race / vet / gofmt / lint) and build"
go test -race ./...
ok "go test -race ./... passed"
go vet ./...
ok "go vet clean"
# vendor/ is upstream code and .claude/ holds agent worktrees, each with a
# vendor/ of its own; neither is this repository's to reformat.
FMT=$(gofmt -l . | grep -v '^vendor/' | grep -v '^\.claude/' || true)
if [ -n "$FMT" ]; then die "gofmt would reformat: $FMT"; fi
ok "gofmt clean"
if command -v golangci-lint >/dev/null; then golangci-lint run ./...; ok "golangci-lint: 0 issues"; else note "golangci-lint not installed — skipped"; fi
mkdir -p bin
go build -o ./bin/farcast ./farsight/cli/cmd/farcast
go build -o ./bin/fatline ./fatline/cmd/fatline
go build -o ./bin/shrike  ./shrike/cmd/shrike
ok "built ./bin/{farcast,fatline,shrike}"

# ---- A1 — FatLine egress + Shrike sidecar over loopback --------------------
step "A1 — FatLine egress + Shrike sidecar (deny-by-default + monitoring)"
if port_open "$EGRESS_PORT"; then die "127.0.0.1:$EGRESS_PORT is already in use"; fi
if port_open "$STATUS_PORT"; then die "127.0.0.1:$STATUS_PORT is already in use"; fi

TMP=$(mktemp -d)
SOCK="$TMP/shrike.sock"
cat > "$TMP/sample-manifest.yaml" <<'EOF'
name: validate
apps:
  - name: web
    containerfile: Containerfile
    external:
      - host: api.stripe.com
        reason: payments
EOF

# FatLine is identified per application since 4.4 (ADR 0013): it reads a policy
# document, not a manifest, and an application is whoever holds the credential
# whose SHA-256 the document names. Two applications here, on purpose — "web"
# declares a host and "worker" declares none — because the property worth
# showing locally is that one cannot use the other's declaration.
#
# Shrike still takes the manifest: its job is to know what was DECLARED, which
# is a different question from who is ASKING.
WEB_CRED=$(openssl rand -hex 32)
WORKER_CRED=$(openssl rand -hex 32)
cat > "$TMP/policy.json" <<EOF
{
  "version": 1,
  "apps": [
    { "name": "web", "namespace": "validate",
      "credential_sha256": "$(printf '%s' "$WEB_CRED" | sha256_hex)",
      "external": [ { "host": "api.stripe.com", "reason": "payments" } ] },
    { "name": "worker", "namespace": "validate",
      "credential_sha256": "$(printf '%s' "$WORKER_CRED" | sha256_hex)" }
  ]
}
EOF

./bin/shrike --socket "$SOCK" --manifest "$TMP/sample-manifest.yaml" --status-listen "127.0.0.1:$STATUS_PORT" >"$TMP/shrike.log" 2>&1 &
SHRIKE_PID=$!
./bin/fatline --egress-listen "127.0.0.1:$EGRESS_PORT" --policy "$TMP/policy.json" --shrike-socket "$SOCK" >"$TMP/fatline.log" 2>&1 &
FATLINE_PID=$!
wait_http "http://127.0.0.1:$STATUS_PORT/_shrike/status" 5 || die "Shrike status endpoint never came up — $TMP/shrike.log"
wait_port "$EGRESS_PORT" 5 || die "FatLine egress port never opened — $TMP/fatline.log"
ok "Shrike + FatLine up (status :$STATUS_PORT, egress :$EGRESS_PORT, 2 applications with policy)"

# The credential rides as proxy userinfo, which every standard client turns into
# a Proxy-Authorization header on its own — that is what lets identity change
# without the application changing (ADR 0013 decision 2).
WEB="http://web:$WEB_CRED@127.0.0.1:$EGRESS_PORT"
WORKER="http://worker:$WORKER_CRED@127.0.0.1:$EGRESS_PORT"
ANON="http://127.0.0.1:$EGRESS_PORT"

# Traffic-generating curls exit non-zero by design (denied/timeout) — ignore them;
# the proof is the Shrike picture, not curl's exit code.
for _ in 1 2 3; do curl -s -o /dev/null -x "$WEB" https://evil.example.com --max-time 3 || true; done
curl -s -o /dev/null -x "$WEB"    http://api.stripe.com  --max-time 3 || true
curl -s -o /dev/null -x "$WEB"    https://api.stripe.com --max-time 5 || true
curl -s -o /dev/null -x "$ANON"   https://api.stripe.com --max-time 3 || true
curl -s -o /dev/null -x "$WORKER" https://api.stripe.com --max-time 3 || true
sleep 1   # let buffered events drain over the sidecar wire
ok "drove 3 denied (undeclared) + 1 cleartext + 1 allowed + 1 unidentified + 1 wrong-application request through the proxy"

curl -fsS "http://127.0.0.1:$STATUS_PORT/_shrike/status" > "$TMP/status.json" || die "could not fetch Shrike status"
note "$(cat "$TMP/status.json")"

if [ "$HAVE_PY" = 1 ]; then
  python3 - "$TMP/status.json" <<'PY' || die "Shrike security-picture assertions failed"
import sys, json
d = json.load(open(sys.argv[1]))
errs = []
if "api.stripe.com" not in d.get("declared", []):
    errs.append("declared should contain api.stripe.com; got %r" % d.get("declared"))
# Keyed by application as well as reason and host: since 4.4 two applications
# denied the same host are two problems, not one, and a picture that merged
# them would hide exactly what this phase enforces.
viol = {(v.get("reason"), v.get("host"), v.get("app", "")): v for v in d.get("violations", [])}
w = viol.get(("not_in_allowlist", "evil.example.com", "web"))
if not w or w.get("severity") != "warning" or w.get("count") != 3:
    errs.append("expected warning x3 for web -> evil.example.com; got %r" % w)
if w and w.get("namespace") != "validate":
    errs.append("the violation should name web's namespace; got %r" % w.get("namespace"))
c = viol.get(("cleartext_not_allowed", "api.stripe.com", "web"))
if not c or c.get("severity") != "info":
    errs.append("expected info cleartext for web -> api.stripe.com; got %r" % c)
if "api.stripe.com" not in {a.get("host") for a in d.get("allowed", [])}:
    errs.append("api.stripe.com should appear under allowed; got %r" % d.get("allowed"))

# The two properties 4.4 added, both invisible before it.
u = viol.get(("unknown_app", "api.stripe.com", ""))
if not u:
    errs.append("a caller with no credential should be refused as unknown_app, unattributed; got %r" % list(viol))
if u and u.get("app"):
    errs.append("an unidentified caller must not be attributed to an application; got %r" % u.get("app"))
x = viol.get(("not_in_allowlist", "api.stripe.com", "worker"))
if not x:
    errs.append("worker must not reach the host web declared; got %r" % list(viol))
for e in errs:
    sys.stderr.write("      - %s\n" % e)
sys.exit(1 if errs else 0)
PY
  ok "verified: declared api.stripe.com · web→evil.example.com warning×3 · cleartext info · api.stripe.com allowed · no-credential unknown_app · worker refused web's host"
else
  grep -q '"declared":\["api.stripe.com"\]' "$TMP/status.json" || die "declared host missing"
  grep -q 'evil.example.com'                "$TMP/status.json" || die "evil.example.com violation missing"
  grep -q 'cleartext_not_allowed'           "$TMP/status.json" || die "cleartext violation missing"
  grep -q '"count":3'                        "$TMP/status.json" || die "expected a count:3 violation"
  grep -q '"unknown_app"'                    "$TMP/status.json" || die "an unidentified caller should be refused as unknown_app"
  grep -q '"app":"worker"'                   "$TMP/status.json" || die "worker should be denied a host it never declared"
  ok "verified (loose grep; install python3 for precise assertions)"
fi

if grep -q "policy violation" "$TMP/shrike.log"; then
  # An alert that cannot say who did it is telemetry. The status JSON named the
  # application from 4.4 while this stream did not, so it is asserted here.
  grep -q 'app=web' "$TMP/shrike.log" || die "Shrike's alert lines do not name the application — see $TMP/shrike.log"
  grep -q 'app=worker' "$TMP/shrike.log" || die "Shrike's alert lines do not distinguish the two applications — see $TMP/shrike.log"
  ok "Shrike raised alert log lines, each naming the application:"
  grep "policy violation" "$TMP/shrike.log" | sed 's/^/        /' | head -6
else
  die "expected Shrike alert lines in $TMP/shrike.log"
fi

kill "$FATLINE_PID" "$SHRIKE_PID" 2>/dev/null || true
wait 2>/dev/null || true
FATLINE_PID=''; SHRIKE_PID=''
ok "stopped FatLine + Shrike"

# ---- A2 — tunnel / crypto / identity --------------------------------------
step "A2 — mTLS tunnel, per-instance CA, and identity tests"
# The full tunnel Connect e2e (good client connects; foreign-CA / wrong-SAN
# rejected) lives in the root fatline package; crypto + identity cover the rest.
go test ./fatline ./fatline/internal/crypto/... ./fatline/identity/...
ok "tunnel e2e + CA mint/verify + operator-SAN identity passed"

# ---- A3 — connect no-cloud surface ----------------------------------------
step "A3 — farcast connect no-cloud surface (exit codes)"
export FARCAST_CONFIG_HOME="$TMP/cfg"
mkdir -p "$FARCAST_CONFIG_HOME"; chmod 700 "$FARCAST_CONFIG_HOME"
expect_exit 2 "connect (no instance)"          ./bin/farcast connect
expect_exit 2 "connect --carrier cp-forward"   ./bin/farcast connect --carrier cp-forward foo
expect_exit 1 "connect (unknown instance)"     ./bin/farcast connect ghost

# ---- done ------------------------------------------------------------------
step "Part A complete"
printf '%s  ✓ Part A passed — deny-by-default boundary, Shrike monitoring, and the connect surface all validated locally (no cloud).%s\n' "$GRN$BOLD" "$RST"
note "Next: Part B (billable) in docs/runbooks/phase-2-validation.md for the real farcast connect."
