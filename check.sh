#!/usr/bin/env bash
#
# The repository check: the guardrails AGENTS.md and ADR 0002 make mandatory,
# for both Go modules — the root module and sdk/go, which the root's ./...
# never reaches. The Apple client's Swift guardrails (ADR 0021 decision 4)
# join this gate with the first client code; until then there is no Swift to
# check.
#
#   1  gofmt over every Go file outside vendor/
#   2  dependencies: go.sum, go.mod and vendor/ agree, byte for byte, and the
#      vendored module count is the reviewed one; the SDK has none at all
#   3  build, natively and for linux/amd64 the way the images are built
#   4  go vet, including the integration- and walk-tagged files (type-checked,
#      never run)
#   5  golangci-lint, mandatory — a missing linter fails the check
#   6  go test -race
#   7  the randomized hand-over model, with --model (minutes)
#
# There is no hosted CI. Run this before every commit and before every live
# walk; it is offline by construction (GOPROXY=off) and touches no cloud.
#
# Usage:  ./check.sh [--model]
#   FARCAST_MODEL=1 is the same as --model; FARCAST_MODEL_SEEDS, _STEPS,
#   _SEED0, _SILENT, _REFUSE, _LOST, _RESTART and _PINFAIL size the model run.
# Exit:   0 pass, 1 a check failed, 2 usage error.

set -euo pipefail

# Changing this is a reviewed, measured decision: the CLI holds cloud
# credentials, so its dependency surface is a security property (ADR 0006).
VENDORED_MODULES=31

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

TMP=''
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP" || true; }
on_err() {
  local rc=$?
  printf '\n%s✗ FAILED during: %s%s\n' "$RED$BOLD" "$STEP" "$RST" >&2
  printf '%s  exit %d at line %s — last command: %s%s\n' \
    "$RED" "$rc" "${1:-?}" "${BASH_COMMAND:-?}" "$RST" >&2
}
trap 'on_err $LINENO' ERR
trap cleanup EXIT

MODEL=''
[ -n "${FARCAST_MODEL:-}" ] && MODEL=1
for arg in "$@"; do
  case "$arg" in
    --model) MODEL=1 ;;
    -h|--help) sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'unknown argument: %s\nusage: ./check.sh [--model]\n' "$arg" >&2; exit 2 ;;
  esac
done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"
TMP=$(mktemp -d)

# An operator's environment must not change what is checked: GOFLAGS could add
# -tags=integration and run cloud tests, a newer toolchain directive could be
# downloaded, a module could be fetched, and a stray go.work would change what
# ./... means. The model is run only by step 7, never inside the race step.
export GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOFLAGS=
unset FARCAST_MODEL

# ---- tools -------------------------------------------------------------------
step "0 — tools"
for tool in go gofmt golangci-lint diff mktemp; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    if [ "$tool" = golangci-lint ]; then
      die "golangci-lint is not on PATH. The lint guardrail is mandatory (AGENTS.md, ADR 0002); install it (e.g. brew install golangci-lint) and re-run."
    fi
    die "$tool is not on PATH"
  fi
done
GOV=$(go env GOVERSION)
WANT=$(awk '$1=="toolchain"{sub(/^go/,"",$2);print $2}' go.mod)
if [ -n "$WANT" ] && ! awk -v have="${GOV#go}" -v want="$WANT" 'BEGIN{
    n=split(have,h,"."); m=split(want,w,".");
    for(i=1;i<=(n>m?n:m);i++){a=(i<=n?h[i]+0:0); b=(i<=m?w[i]+0:0); if(a>b) exit 0; if(a<b) exit 1}
    exit 0}'; then
  die "go is $GOV, older than the module's toolchain go$WANT. The images build with golang:1.27 (fatline/Containerfile), so an older local Go checks code the images never compile."
fi
LINT=$(golangci-lint version 2>&1 | head -n1)
ok "$GOV (module toolchain go$WANT)"
ok "$LINT"

# ---- 1. gofmt ------------------------------------------------------------------
step "1 — gofmt (both modules)"
# Pruned rather than filtered: never run 'gofmt -w .' at the root — it rewrites
# vendor/, which step 2 would then refuse.
FMT=$(find . \( -path ./vendor -o -path ./.claude -o -path ./.git -o -path ./bin \) -prune \
  -o -name '*.go' -type f -print0 | xargs -0 gofmt -l)
if [ -n "$FMT" ]; then
  printf '%s\n' "$FMT" >&2
  die "gofmt would change the files above; format them one by one (gofmt -w <file>), never the repository root"
fi
ok "every Go file is formatted"

# ---- 2. dependencies -------------------------------------------------------------
offline_hint() {
  if grep -q 'module lookup disabled by GOPROXY=off' "$1" 2>/dev/null; then
    die "the module cache lacks a vendored module; this check never fetches. Populate it deliberately with 'go mod download' (contacts your GOPROXY), then re-run."
  fi
  cat "$1" >&2
  die "$2"
}

step "2 — dependencies, root module"
go mod verify >"$TMP/verify.log" 2>&1 || offline_hint "$TMP/verify.log" "go mod verify failed: the module cache does not match go.sum"
ok "go mod verify"
go mod tidy -diff >"$TMP/tidy.log" 2>&1 || offline_hint "$TMP/tidy.log" "go.mod/go.sum are not what the code needs (go mod tidy -diff)"
ok "go mod tidy -diff"
# go build -mod=vendor checks modules.txt against go.mod and nothing more: a
# hand edit inside vendor/, or a stray 'gofmt -w .', is invisible to it.
go mod vendor -o "$TMP/vendor" >"$TMP/vendor.log" 2>&1 || offline_hint "$TMP/vendor.log" "go mod vendor failed"
if ! diff -r vendor "$TMP/vendor" >"$TMP/vendor.diff" 2>&1; then
  diff -rq vendor "$TMP/vendor" 2>&1 | head -n 20 >&2 || true
  die "vendor/ is not exactly what 'go mod vendor' produces (above); restore it with 'go mod vendor'"
fi
ok "vendor/ is byte-identical to go mod vendor"
n=$(grep -c '^# ' vendor/modules.txt)
if [ "$n" -ne "$VENDORED_MODULES" ]; then
  die "vendored modules: expected $VENDORED_MODULES, found $n. A dependency change is a reviewed, measured decision (ADR 0007/0009 discipline): record it and update VENDORED_MODULES in check.sh in the same commit."
fi
ok "$n vendored modules"

step "2b — dependencies, sdk/go"
(
  cd sdk/go
  go mod verify >"$TMP/sdk-verify.log" 2>&1 || { cat "$TMP/sdk-verify.log" >&2; exit 1; }
  go mod tidy -diff >"$TMP/sdk-tidy.log" 2>&1 || { cat "$TMP/sdk-tidy.log" >&2; exit 1; }
  mods=$(go list -m all)
  [ "$mods" = "github.com/sofmon/farcast/sdk/go" ] || { printf '%s\n' "$mods" >&2; exit 1; }
  [ ! -e go.sum ] && [ ! -e vendor ]
) || die "the SDK module has gained a dependency, or its go.mod is not tidy. It is the public import surface and has none by design (PLAN.md)."
ok "sdk/go has no dependencies"

# ---- 3. build --------------------------------------------------------------------
step "3 — build"
go build -mod=vendor ./...
ok "root, native"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -mod=vendor -trimpath ./...
ok "root, linux/amd64 without cgo — how the images are built"
(cd sdk/go && go build ./... && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath ./...)
ok "sdk/go, native and linux/amd64"

# ---- 4. vet ----------------------------------------------------------------------
step "4 — go vet"
go vet -mod=vendor ./...
ok "root"
# Type-checks the integration- and walk-tagged tests, which nothing else
# compiles. They are never RUN here: they touch billable cloud, or a live
# instance.
go vet -mod=vendor -tags=integration,walk ./...
ok "root, with the integration- and walk-tagged files"
(cd sdk/go && go vet ./...)
ok "sdk/go"

# ---- 5. lint ---------------------------------------------------------------------
step "5 — golangci-lint"
golangci-lint run --config "$ROOT/.golangci.yml" --build-tags=integration,walk ./...
ok "root: 0 issues"
(cd sdk/go && golangci-lint run --config "$ROOT/.golangci.yml" ./...)
ok "sdk/go: 0 issues"

# ---- 6. race tests ---------------------------------------------------------------
step "6 — go test -race"
go test -mod=vendor -race ./...
ok "root"
(cd sdk/go && go test -race ./...)
ok "sdk/go"

# ---- 7. model --------------------------------------------------------------------
MODELNOTE="model: not run (--model)"
if [ -n "$MODEL" ]; then
  step "7 — the randomized hand-over model"
  FARCAST_MODEL=1 go test -mod=vendor -count=1 -timeout 30m -run '^TestHandOverModel' ./farsight/cli/internal/cli/
  ok "the model passes"
  MODELNOTE="model: passed"
fi

STEP="(done)"
printf '\n%scheck passed: root + sdk/go · %s · %s · %s vendored modules · %s%s\n' \
  "$GRN$BOLD" "$GOV" "$(printf '%s' "$LINT" | awk '{print "golangci-lint " $4}')" "$n" "$MODELNOTE" "$RST"
