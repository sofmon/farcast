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
FMT=$(gofmt -l . | grep -v '^vendor/' || true)
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

./bin/shrike --socket "$SOCK" --manifest "$TMP/sample-manifest.yaml" --status-listen "127.0.0.1:$STATUS_PORT" >"$TMP/shrike.log" 2>&1 &
SHRIKE_PID=$!
./bin/fatline --egress-listen "127.0.0.1:$EGRESS_PORT" --manifest "$TMP/sample-manifest.yaml" --shrike-socket "$SOCK" >"$TMP/fatline.log" 2>&1 &
FATLINE_PID=$!
wait_http "http://127.0.0.1:$STATUS_PORT/_shrike/status" 5 || die "Shrike status endpoint never came up — $TMP/shrike.log"
wait_port "$EGRESS_PORT" 5 || die "FatLine egress port never opened — $TMP/fatline.log"
ok "Shrike + FatLine up (status :$STATUS_PORT, egress :$EGRESS_PORT)"

PX="http://127.0.0.1:$EGRESS_PORT"
# Traffic-generating curls exit non-zero by design (denied/timeout) — ignore them;
# the proof is the Shrike picture, not curl's exit code.
for _ in 1 2 3; do curl -s -o /dev/null -x "$PX" https://evil.example.com --max-time 3 || true; done
curl -s -o /dev/null -x "$PX" http://api.stripe.com  --max-time 3 || true
curl -s -o /dev/null -x "$PX" https://api.stripe.com --max-time 5 || true
sleep 1   # let buffered events drain over the sidecar wire
ok "drove 3 denied (undeclared) + 1 cleartext + 1 allowed request through the proxy"

curl -fsS "http://127.0.0.1:$STATUS_PORT/_shrike/status" > "$TMP/status.json" || die "could not fetch Shrike status"
note "$(cat "$TMP/status.json")"

if [ "$HAVE_PY" = 1 ]; then
  python3 - "$TMP/status.json" <<'PY' || die "Shrike security-picture assertions failed"
import sys, json
d = json.load(open(sys.argv[1]))
errs = []
if "api.stripe.com" not in d.get("declared", []):
    errs.append("declared should contain api.stripe.com; got %r" % d.get("declared"))
viol = {(v.get("reason"), v.get("host")): v for v in d.get("violations", [])}
w = viol.get(("not_in_allowlist", "evil.example.com"))
if not w or w.get("severity") != "warning" or w.get("count") != 3:
    errs.append("expected warning x3 for evil.example.com; got %r" % w)
c = viol.get(("cleartext_not_allowed", "api.stripe.com"))
if not c or c.get("severity") != "info":
    errs.append("expected info cleartext for api.stripe.com; got %r" % c)
if "api.stripe.com" not in {a.get("host") for a in d.get("allowed", [])}:
    errs.append("api.stripe.com should appear under allowed; got %r" % d.get("allowed"))
for e in errs:
    sys.stderr.write("      - %s\n" % e)
sys.exit(1 if errs else 0)
PY
  ok "verified: declared api.stripe.com · evil.example.com warning×3 · cleartext info · api.stripe.com allowed"
else
  grep -q '"declared":\["api.stripe.com"\]' "$TMP/status.json" || die "declared host missing"
  grep -q 'evil.example.com'                "$TMP/status.json" || die "evil.example.com violation missing"
  grep -q 'cleartext_not_allowed'           "$TMP/status.json" || die "cleartext violation missing"
  grep -q '"count":3'                        "$TMP/status.json" || die "expected a count:3 violation"
  ok "verified (loose grep; install python3 for precise assertions)"
fi

if grep -q "policy violation" "$TMP/shrike.log"; then
  ok "Shrike raised alert log lines:"
  grep "policy violation" "$TMP/shrike.log" | sed 's/^/        /' | head -5
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
