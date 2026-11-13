#!/usr/bin/env bash
#
# The repository check: the guardrails AGENTS.md and ADR 0002 make mandatory,
# for both Go modules — the root module and sdk/go, which the root's ./...
# never reaches — and the Apple client's Swift guardrails (ADR 0021 decision
# 4), so it needs a Mac with Xcode.
#
#   1  gofmt over every Go file outside vendor/
#   2  dependencies: go.sum, go.mod and vendor/ agree, byte for byte, and the
#      vendored module count is the reviewed one; the SDK has none at all
#   3  build, natively and for linux/amd64 the way the images are built
#   4  go vet, including the integration- and walk-tagged files (type-checked,
#      never run)
#   5  golangci-lint, mandatory — a missing linter fails the check
#   6  go test -race
#   7  the Apple client: the source gate (only allowed file types and the
#      one backdrop image, no links; the CLI's vectors and FatLine's PKI
#      vectors copied byte for byte; no unsafe, unsafeFlags or attribute
#      outside an allowed set, outside the reviewed allowlist; a static
#      manifest with no third-party package and each target's settings and
#      resources from an allowlist; the project held to an exact shape,
#      reviewed setting keys, one Info.plist holding only the build's commit,
#      and one action-free scheme; the guardrails in effect for every
#      configuration and SDK), swift build and swift test, the app built for
#      macOS, the iOS simulator and the visionOS simulator, and xcodebuild
#      test on macOS and an iOS simulator (minutes, the first time). Each of
#      the three test runs includes ADR 0020's Apple regression: mutual TLS
#      from URLSession and NWConnection to Go servers built from the PKI
#      vectors and FatLine's ServerTLSConfig, on 127.0.0.1, whose live tests
#      must all pass by name
#   8  the randomized hand-over model, with --model (minutes)
#
# There is no hosted CI. Run this before every commit and before every live
# walk; it is offline by construction (GOPROXY=off, and a Swift client with
# nothing to resolve) and touches no cloud.
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
# ADR 0020's Apple regression server (step 7b) reads a FIFO this shell holds
# open on descriptor 9: closing it is the server's signal to stop, and the
# kill makes sure of it. bash hands descriptor 9 to every child, so each
# long-running command started while it is open (swift test, every
# xcodebuild, and the $(...) shell kit_test runs in) closes it first: then
# this shell is its only holder, and the server stops however the check
# ends, even when a kill -9 leaves no chance to clean up.
FIXTURE_PID=''
fixture_stop() {
  exec 9>&-
  [ -n "$FIXTURE_PID" ] && { kill "$FIXTURE_PID" 2>/dev/null; wait "$FIXTURE_PID" 2>/dev/null; } || true
  FIXTURE_PID=''
}
cleanup() { fixture_stop; [ -n "$TMP" ] && rm -rf "$TMP" || true; }
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
    -h|--help) awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit 0 ;;
    *) printf 'unknown argument: %s\nusage: ./check.sh [--model]\n' "$arg" >&2; exit 2 ;;
  esac
done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"
TMP=$(mktemp -d)

# An operator's environment must not change what is checked: GOFLAGS could add
# -tags=integration and run cloud tests, a newer toolchain directive could be
# downloaded, a module could be fetched, and a stray go.work would change what
# ./... means. The model is run only by step 8, never inside the race step.
export GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOFLAGS=
unset FARCAST_MODEL
# Likewise for Xcode: XCODE_XCCONFIG_FILE overrides every build setting of
# every target, so a stray one could switch a Swift guardrail off.
unset XCODE_XCCONFIG_FILE

# ---- tools -------------------------------------------------------------------
step "0 — tools"
for tool in go gofmt golangci-lint diff mktemp mkfifo; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    if [ "$tool" = golangci-lint ]; then
      die "golangci-lint is not on PATH. The lint guardrail is mandatory (AGENTS.md, ADR 0002); install it (e.g. brew install golangci-lint) and re-run."
    fi
    die "$tool is not on PATH"
  fi
done
# The Swift guardrails are as mandatory as the Go ones (ADR 0021 decision 4):
# a machine that cannot run them cannot pass the check.
[ "$(uname -s)" = Darwin ] || die "the Apple client's guardrails need macOS with Xcode (ADR 0021 decision 4); this is $(uname -s)"
for tool in swift xcodebuild xcrun; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is not on PATH. The Apple client's guardrails need Xcode (ADR 0021 decision 4); install it and run xcode-select."
done
# First lines are read with awk, which drains its input: under pipefail, a
# 'head -n1' that closes the pipe early fails the check with SIGPIPE.
XCODE=$(xcodebuild -version 2>/dev/null | awk 'NR == 1')
[ -n "$XCODE" ] || die "xcodebuild cannot find Xcode; point xcode-select at it (xcode-select -s /Applications/Xcode.app)"
SWIFTV=$(swift --version 2>/dev/null | awk 'NR == 1' | sed 's/.*Swift version \([0-9.]*\).*/\1/')
GOV=$(go env GOVERSION)
WANT=$(awk '$1=="toolchain"{sub(/^go/,"",$2);print $2}' go.mod)
if [ -n "$WANT" ] && ! awk -v have="${GOV#go}" -v want="$WANT" 'BEGIN{
    n=split(have,h,"."); m=split(want,w,".");
    for(i=1;i<=(n>m?n:m);i++){a=(i<=n?h[i]+0:0); b=(i<=m?w[i]+0:0); if(a>b) exit 0; if(a<b) exit 1}
    exit 0}'; then
  die "go is $GOV, older than the module's toolchain go$WANT. The images build with golang:1.27 (fatline/Containerfile), so an older local Go checks code the images never compile."
fi
LINT=$(golangci-lint version 2>&1 | awk 'NR == 1')
ok "$GOV (module toolchain go$WANT)"
ok "$LINT"
ok "$XCODE, Swift $SWIFTV"

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
vendored=$(grep -c '^# ' vendor/modules.txt)
if [ "$vendored" -ne "$VENDORED_MODULES" ]; then
  die "vendored modules: expected $VENDORED_MODULES, found $vendored. A dependency change is a reviewed, measured decision (ADR 0007/0009 discipline): record it and update VENDORED_MODULES in check.sh in the same commit."
fi
ok "$vendored vendored modules"

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

# ---- 7. the Apple client ---------------------------------------------------------
APPLE=farsight/client/apple
KIT=$APPLE/FarSightKit
PROJECT=$APPLE/FarSight.xcodeproj
ALLOW=$APPLE/unsafe-allowlist.txt
# Kept between runs (and ignored by git) so the Xcode builds are incremental.
DERIVED=$APPLE/.build/DerivedData
# Every source file of the client, skipping build output.
# Pruned by exact path only — build output, and the per-user state Xcode
# writes inside the project — so no directory name can hide a source.
apple_files() {
  find "$APPLE" \( -path "$APPLE/.build" -o -path "$KIT/.build" -o -path "$KIT/.swiftpm" \
    -o -path "$PROJECT/xcuserdata" -o -path "$PROJECT/project.xcworkspace/xcuserdata" \) -prune -o "$@" -print0
}
# The number of tests a Swift Testing log reports; a run of none is a failure.
counted() {
  awk '/Test run with [0-9]+ tests/ { for (i = 1; i < NF; i++) if ($i == "with") n += $(i + 1) } END { print n + 0 }' "$1"
}
# ADR 0020's Apple regression (step 7b starts its servers): a skipped test
# still counts in "Test run with N tests", so the count cannot see a run that
# silently skipped the live tests. Each run must report every one of them
# passed, by name, and none skipped or failed.
REGRESSION_LIVE=7
live_passed() {  # <log> <what>
  local n bad
  n=$(grep -cE 'Test "ADR 0020 live: [^"]*" passed after' "$1" || true)
  bad=$(grep -cE 'Test "ADR 0020 live: [^"]*" (skipped|failed)' "$1" || true)
  [ "$n" -eq "$REGRESSION_LIVE" ] && [ "$bad" -eq 0 ] \
    || { tail -n 20 "$TMP/applefixture.log" >&2; die "$2: $n of the $REGRESSION_LIVE ADR 0020 live tests passed"; }
}

step "7a — Swift source gate"
# What is in the tree at all: no links, which could pull in sources from
# anywhere, and only the file types the client is made of. C, C++,
# Objective-C, assembly, an .xcconfig or a build script would each compile or
# configure something outside the Swift guardrails; a new type is added here
# in a reviewed commit. One image is allowed by its path, not its type: the
# backdrop, which the app decodes and never runs, painted by the test
# target's BackdropPainter and checked by BackdropTests against it and
# against the readability cap.
BACKDROP=$KIT/Sources/FarSightUI/Backdrop/backdrop.heic
links=$(apple_files -type l | tr '\0' '\n')
[ -z "$links" ] || { printf '%s\n' "$links" >&2; die "symbolic links in the Apple client (above) could bring in sources no check sees"; }
strays=$(apple_files -type f ! -name .DS_Store | tr '\0' '\n' | awk -F/ -v backdrop="$BACKDROP" '{ n = split($NF, part, "."); ext = (n > 1 ? part[n] : "") }
  $0 != backdrop && ext !~ /^(swift|json|md|txt|pbxproj|xcscheme|xcworkspacedata|plist)$/ { print }')
[ -z "$strays" ] || { printf '%s\n' "$strays" >&2; die "files of a type the Apple client does not allow (above); a new type is a reviewed change to this step"; }
ok "only Swift sources and their manifests, project, data and the backdrop; no links"

# Go's golden vectors, which FarSightKit's tests decode from copies: the
# CLI's (ADR 0021 decision 7, Verification 4), which Go's tests hold to what
# the CLI prints, and FatLine's PKI vectors (ADR 0020), which Go's tests hold
# to what crypto.go issues and the Apple regression serves. So each copy must
# be Go's own, byte for byte, and hold nothing Go's does not: a copy edited
# to make a Swift test pass would hide a broken contract. Finder's .DS_Store
# is ignored on both sides, as the file-type step above ignores it.
vector_copy() {  # <go testdata> <kit Vectors> "<subdirs>"
  local go=$1 kit=$2 dirs=$3 have d
  [ -d "$kit" ] || die "FarSightKit has no copy of Go's vectors at $kit"
  have=$(find "$kit" -mindepth 1 -maxdepth 1 ! -name .DS_Store -print | sed "s|^$kit/||" | sort | paste -sd' ' -)
  [ "$have" = "$dirs" ] || die "FarSightKit's vectors at $kit hold '$have', not Go's '$dirs'"
  for d in $dirs; do
    [ -d "$go/$d" ] || die "Go has no $d vectors at $go/$d"
    if ! diff -r -x .DS_Store "$go/$d" "$kit/$d" >"$TMP/vectors.diff" 2>&1; then
      head -n 20 "$TMP/vectors.diff" >&2
      die "FarSightKit's copy of $go/$d is not Go's (above). Copy it again: rm -rf '$kit/$d' && cp -R '$go/$d' '$kit/'"
    fi
  done
  ok "FarSightKit decodes Go's own vectors from $go ($dirs), byte for byte"
}
vector_copy farsight/cli/internal/cli/testdata "$KIT/Tests/FarSightCoreTests/Vectors" "app instances kinds version world"
vector_copy fatline/internal/crypto/testdata   "$KIT/Tests/FarSightTLSTests/Vectors"  "pki"

# Strict memory safety flags unsafe constructs but not every way around it:
# @unchecked Sendable (ADR 0021 decision 4), an 'unsafe' marker, unsafeFlags,
# and attributes such as @_silgen_name (binds any C symbol), @diagnose (turns
# a diagnostic group off), @preconcurrency or @safe. So attributes are held
# to an allowlist, and every line is scanned — comments and strings included,
# because telling them apart takes a parser and rewording a comment is cheap.
# Every hit outside the reviewed allowlist file fails.
ATTRIBUTES="Test Suite testable main Observable ObservationIgnored State Binding Bindable Environment GestureState FocusState Namespace ViewBuilder MainActor Sendable escaping autoclosure discardableResult available"
hits=$(apple_files -name '*.swift' -type f | xargs -0 awk -v allowed="$ATTRIBUTES" '
  BEGIN { n = split(allowed, list, " "); for (i = 1; i <= n; i++) ok[list[i]] = 1 }
  {
    bad = ($0 ~ /nonisolated[ \t]*\([ \t]*unsafe|(^|[^A-Za-z0-9_])unsafe([^A-Za-z0-9_]|$)|unsafeFlags|@[^A-Za-z]/)
    rest = $0
    while (match(rest, /@[A-Za-z_][A-Za-z0-9_]*/)) {
      if (!(substr(rest, RSTART + 1, RLENGTH - 1) in ok)) bad = 1
      rest = substr(rest, RSTART + RLENGTH)
    }
    if (bad) print FILENAME ":" FNR ":" $0
  }') || die "the source gate could not read every Swift file"
if [ -n "$hits" ]; then
  unallowed=$(printf '%s\n' "$hits" | while IFS= read -r hit; do
    file=${hit%%:*}; text=${hit#*:*:}; trimmed=$(printf '%s' "$text" | sed 's/^[[:space:]]*//')
    if [ ! -f "$ALLOW" ] || ! grep -qxF "$file | $trimmed" "$ALLOW"; then printf '%s\n' "$hit"; fi
  done)
  if [ -n "$unallowed" ]; then
    printf '%s\n' "$unallowed" >&2
    die "Swift above uses unsafe, unsafeFlags or an attribute outside the allowed set ($ATTRIBUTES). Rewrite it, or add '<path> | <trimmed line>' to $ALLOW, or an attribute to this step, in a reviewed commit that says why."
  fi
fi
ok "no unsafe, unsafeFlags or attribute outside the allowed set, outside the allowlist"

# The package, as SwiftPM sees it. The manifest is Swift that runs, so it is
# held static first — nothing it does may depend on where or how it is
# evaluated — and then read: no dependency (decision 3), only ordinary and
# test targets (a binary, system-library, plugin or macro target brings in
# code no guardrail covers), and each target's settings drawn from an
# allowlist: the three guardrails, unconditional and all present, and
# main-actor default isolation.
[ -z "$(find "$KIT" -maxdepth 1 -name 'Package@*.swift')" ] || die "FarSightKit has a version-specific manifest (Package@…swift), which SwiftPM would read instead of Package.swift"
if grep -nE '#if|#file|#line|#dsohandle|CommandLine|Context|ProcessInfo|getenv|environment|FileManager|Darwin|^[[:space:]]*import[[:space:]]' "$KIT/Package.swift" | grep -vE '^[0-9]+:import PackageDescription$'; then
  die "FarSightKit/Package.swift (above) branches on its environment or imports more than PackageDescription; the manifest must be static"
fi
(cd "$KIT" && swift package dump-package >"$TMP/package.json" 2>"$TMP/package.err") \
  || { cat "$TMP/package.err" >&2; die "swift package dump-package failed"; }
pj() { plutil -extract "$1" "$2" -o - "$TMP/package.json" 2>/dev/null; }
[ "$(pj dependencies raw)" = 0 ] || die "FarSightKit has gained a package dependency. The first one needs an ADR (ADR 0021 decision 3)."
targets=$(pj targets raw)
[ "${targets:-0}" -gt 0 ] || die "FarSightKit declares no targets; dump-package output was not understood"
GUARDRAILS='{"kind":{"swiftLanguageMode":{"_0":"6"}},"tool":"swift"}
{"kind":{"strictMemorySafety":{}},"tool":"swift"}
{"kind":{"treatAllWarnings":{"_0":"error"}},"tool":"swift"}'
ALLOWED_SETTINGS="$GUARDRAILS
{\"kind\":{\"defaultIsolation\":{\"_0\":\"MainActor\"}},\"tool\":\"swift\"}"
# Resources, by target, exact path and rule: data a target ships or a test
# reads. A 'process' rule runs a build tool over the file.
RESOURCES='FarSightUI|Backdrop/backdrop.heic|{"copy":{}}
FarSightFixtures|world.json|{"copy":{}}
FarSightCoreTests|Vectors|{"copy":{}}
FarSightTLSTests|Vectors|{"copy":{}}'
for ((t = 0; t < targets; t++)); do
  name=$(pj "targets.$t.name" raw); type=$(pj "targets.$t.type" raw)
  case "$type" in regular|test) ;; *) die "FarSightKit target $name is a $type target; only regular and test targets are allowed without an ADR" ;; esac
  # Sources come from the target's own folder under Sources/ or Tests/,
  # where the gate reads them: no custom path, source list or exclusion.
  ! pj "targets.$t.path" raw >/dev/null && ! pj "targets.$t.sources" raw >/dev/null && [ "$(pj "targets.$t.exclude" raw)" = 0 ] \
    || die "FarSightKit target $name takes its sources from a custom path, list or exclusion"
  count=$(pj "targets.$t.settings" raw || echo 0)
  entries=''
  for ((i = 0; i < count; i++)); do
    entry=$(pj "targets.$t.settings.$i" json)
    printf '%s\n' "$ALLOWED_SETTINGS" | grep -qxF "$entry" \
      || die "FarSightKit target $name has a setting outside the allowlist: $entry (ADR 0021 decision 4)"
    entries="$entries$entry"$'\n'
  done
  while IFS= read -r want; do
    printf '%s' "$entries" | grep -qxF "$want" || die "FarSightKit target $name lacks the guardrail setting $want (ADR 0021 decision 4)"
  done <<<"$GUARDRAILS"
  rcount=$(pj "targets.$t.resources" raw || echo 0)
  rgot=''
  for ((i = 0; i < rcount; i++)); do
    rgot="$rgot$name|$(pj "targets.$t.resources.$i.path" raw)|$(pj "targets.$t.resources.$i.rule" json)"$'\n'
  done
  rgot=$(printf '%s' "$rgot" | sed '/^$/d')
  rwant=$(printf '%s\n' "$RESOURCES" | awk -F'|' -v n="$name" '$1 == n')
  [ "$rgot" = "$rwant" ] || die "FarSightKit target $name declares the resources '$rgot', not the reviewed '$rwant'"
done
ok "FarSightKit: a static manifest, no dependencies; $targets targets, each with exactly the allowed settings and resources"

# The app, as Xcode builds it, held to an exact shape rather than a
# denylist: these objects in these numbers (no build-script phase, no second
# target, file reference or package), sources only through the FarCast
# folder with no exceptions, build settings drawn from an allowlist of keys
# with the guardrails written as literals, and one scheme with no actions.
# Then the guardrails as xcodebuild resolves them, for every configuration
# and SDK.
plutil -convert json -o "$TMP/project.json" "$PROJECT/project.pbxproj" 2>/dev/null \
  || die "FarSight.xcodeproj/project.pbxproj could not be read as a property list"
# Every object is read field by field, from the objects dictionary itself
# (plutil keeps no key order, so the JSON's text is never matched as a
# whole), and each object may carry exactly the fields its type has today:
# a new field — a path on a group, a script, a dependency — is a reviewed
# change to this step.
ids=$(plutil -extract objects raw -o - "$PROJECT/project.pbxproj" 2>/dev/null) || die "FarSight.xcodeproj has no objects"
# Plain ids only: a dot or a space in a key would hide an object from the
# key paths and the word splitting below.
strange=$(printf '%s\n' "$ids" | grep -vxE '[0-9A-F]{24}' || true)
[ -z "$strange" ] || die "FarSight.xcodeproj has objects with unexpected ids: $strange"
px() { plutil -extract "objects.$1.$2" raw -o - "$PROJECT/project.pbxproj" 2>/dev/null; }
isas=$(for id in $ids; do px "$id" isa; done | sort | uniq -c | awk '{ print $2 "=" $1 }' | paste -sd' ' -)
SHAPE="PBXBuildFile=3 PBXFileReference=1 PBXFileSystemSynchronizedRootGroup=1 PBXFrameworksBuildPhase=1 PBXGroup=2 PBXNativeTarget=1 PBXProject=1 PBXResourcesBuildPhase=1 PBXSourcesBuildPhase=1 XCBuildConfiguration=4 XCConfigurationList=2 XCLocalSwiftPackageReference=1 XCSwiftPackageProductDependency=3"
[ "$isas" = "$SHAPE" ] || die "FarSight.xcodeproj's objects are '$isas', not the reviewed shape '$SHAPE'"
FIELDS="PBXBuildFile:isa,productRef
PBXFileReference:explicitFileType,includeInIndex,isa,path,sourceTree
PBXFileSystemSynchronizedRootGroup:isa,path,sourceTree
PBXFrameworksBuildPhase:buildActionMask,files,isa,runOnlyForDeploymentPostprocessing
PBXGroup:children,isa,name,sourceTree
PBXGroup:children,isa,sourceTree
PBXNativeTarget:buildConfigurationList,buildPhases,buildRules,dependencies,fileSystemSynchronizedGroups,isa,name,packageProductDependencies,productName,productReference,productType
PBXProject:attributes,buildConfigurationList,developmentRegion,hasScannedForEncodings,isa,knownRegions,mainGroup,minimizedProjectReferenceProxies,packageReferences,preferredProjectObjectVersion,productRefGroup,projectDirPath,projectRoot,targets
PBXResourcesBuildPhase:buildActionMask,files,isa,runOnlyForDeploymentPostprocessing
PBXSourcesBuildPhase:buildActionMask,files,isa,runOnlyForDeploymentPostprocessing
XCBuildConfiguration:buildSettings,isa,name
XCConfigurationList:buildConfigurations,defaultConfigurationIsVisible,defaultConfigurationName,isa
XCLocalSwiftPackageReference:isa,relativePath
XCSwiftPackageProductDependency:isa,package,productName"
configs=''
for id in $ids; do
  isa=$(px "$id" isa)
  fields=$(plutil -extract "objects.$id" raw -o - "$PROJECT/project.pbxproj" | sort | paste -sd, -)
  printf '%s\n' "$FIELDS" | grep -qxF "$isa:$fields" || die "FarSight.xcodeproj's $isa $id has the fields '$fields', outside the reviewed shape"
  case "$isa" in
    PBXProject)
      [ "$(px "$id" projectDirPath)" = '' ] && [ "$(px "$id" projectRoot)" = '' ] || die "FarSight.xcodeproj moves its project root"
      [ "$(plutil -extract "objects.$id.attributes" raw -o - "$PROJECT/project.pbxproj" | sort | paste -sd, -)" = BuildIndependentTargetsInParallel,LastSwiftUpdateCheck,LastUpgradeCheck,TargetAttributes ] \
        || die "FarSight.xcodeproj's project attributes are outside the reviewed shape" ;;
    PBXGroup)
      # The main group holds the FarCast folder and Products; Products holds
      # the app. Neither has a path of its own.
      [ "$(px "$id" sourceTree)" = '<group>' ] || die "FarSight.xcodeproj has a group outside the project folder"
      case "$(px "$id" name)" in
        Products) [ "$(px "$id" children)" = 1 ] || die "FarSight.xcodeproj's Products group holds more than the app" ;;
        '') [ "$(px "$id" children)" = 2 ] || die "FarSight.xcodeproj's main group holds more than the FarCast folder and Products" ;;
        *) die "FarSight.xcodeproj has an unexpected group" ;;
      esac ;;
    PBXNativeTarget)
      [ "$(px "$id" buildPhases)" = 3 ] && [ "$(px "$id" buildRules)" = 0 ] && [ "$(px "$id" dependencies)" = 0 ] \
        || die "FarSight.xcodeproj's target has build phases, rules or dependencies outside its reviewed shape" ;;
    PBXFileSystemSynchronizedRootGroup)
      [ "$(px "$id" path)" = FarCast ] && [ "$(px "$id" sourceTree)" = '<group>' ] \
        || die "FarSight.xcodeproj compiles from somewhere other than its FarCast folder" ;;
    XCLocalSwiftPackageReference)
      [ "$(px "$id" relativePath)" = FarSightKit ] || die "FarSight.xcodeproj's one package is not FarSightKit" ;;
    PBXFileReference)
      [ "$(px "$id" path)" = FarCast.app ] && [ "$(px "$id" sourceTree)" = BUILT_PRODUCTS_DIR ] && [ "$(px "$id" explicitFileType)" = wrapper.application ] \
        || die "FarSight.xcodeproj's one file reference is not the FarCast.app product" ;;
    PBXSourcesBuildPhase|PBXResourcesBuildPhase)
      [ "$(px "$id" files)" = 0 ] || die "FarSight.xcodeproj has a source or resource outside its FarCast folder" ;;
    XCBuildConfiguration)
      configs="$configs $id" ;;
  esac
done
[ -z "$(apple_files -name Package.resolved | tr '\0' '\n')" ] || die "the Apple client has resolved a package"
SETTING_KEYS="ALWAYS_SEARCH_USER_PATHS CLANG_ENABLE_MODULES CLANG_ENABLE_OBJC_ARC CODE_SIGN_IDENTITY[sdk=macosx*] CODE_SIGN_STYLE COPY_PHASE_STRIP CURRENT_PROJECT_VERSION DEBUG_INFORMATION_FORMAT ENABLE_HARDENED_RUNTIME ENABLE_NS_ASSERTIONS ENABLE_PREVIEWS ENABLE_STRICT_OBJC_MSGSEND ENABLE_TESTABILITY ENABLE_USER_SCRIPT_SANDBOXING GCC_OPTIMIZATION_LEVEL GCC_PREPROCESSOR_DEFINITIONS GENERATE_INFOPLIST_FILE INFOPLIST_FILE INFOPLIST_KEY_CFBundleDisplayName INFOPLIST_KEY_LSApplicationCategoryType INFOPLIST_KEY_UIApplicationSceneManifest_Generation[sdk=iphoneos*] INFOPLIST_KEY_UIApplicationSceneManifest_Generation[sdk=iphonesimulator*] INFOPLIST_KEY_UILaunchScreen_Generation[sdk=iphoneos*] INFOPLIST_KEY_UILaunchScreen_Generation[sdk=iphonesimulator*] INFOPLIST_KEY_UISupportedInterfaceOrientations_iPad INFOPLIST_KEY_UISupportedInterfaceOrientations_iPhone IPHONEOS_DEPLOYMENT_TARGET LD_RUNPATH_SEARCH_PATHS LD_RUNPATH_SEARCH_PATHS[sdk=macosx*] MACOSX_DEPLOYMENT_TARGET MARKETING_VERSION ONLY_ACTIVE_ARCH PRODUCT_BUNDLE_IDENTIFIER PRODUCT_NAME SDKROOT SUPPORTED_PLATFORMS SUPPORTS_MACCATALYST SWIFT_ACTIVE_COMPILATION_CONDITIONS SWIFT_COMPILATION_MODE SWIFT_DEFAULT_ACTOR_ISOLATION SWIFT_OPTIMIZATION_LEVEL SWIFT_STRICT_CONCURRENCY SWIFT_STRICT_MEMORY_SAFETY SWIFT_TREAT_WARNINGS_AS_ERRORS SWIFT_VERSION TARGETED_DEVICE_FAMILY XROS_DEPLOYMENT_TARGET"
literals=0
infoplists=0
for id in $configs; do
  keys=$(plutil -extract "objects.$id.buildSettings" raw -o - "$PROJECT/project.pbxproj" 2>/dev/null || true)
  # One key per line, compared whole: never word-split.
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    case "$key" in *[[:space:]]*) die "FarSight.xcodeproj has a build-setting key with whitespace: '$key'" ;; esac
    case " $SETTING_KEYS " in *" $key "*) ;; *) die "FarSight.xcodeproj sets $key, outside the reviewed build-setting keys" ;; esac
  done <<<"$keys"
  # Values Xcode hands straight to swiftc are held to what is reviewed too.
  case " $(printf '%s ' $keys)" in *" SWIFT_OPTIMIZATION_LEVEL "*)
    case "$(plutil -extract "objects.$id.buildSettings.SWIFT_OPTIMIZATION_LEVEL" raw -o - "$PROJECT/project.pbxproj")" in
      -Onone|-O|-Osize) ;; *) die "FarSight.xcodeproj sets SWIFT_OPTIMIZATION_LEVEL to something other than -Onone, -O or -Osize" ;;
    esac ;;
  esac
  case " $(printf '%s ' $keys)" in *" SWIFT_COMPILATION_MODE "*)
    case "$(plutil -extract "objects.$id.buildSettings.SWIFT_COMPILATION_MODE" raw -o - "$PROJECT/project.pbxproj")" in
      wholemodule|singlefile) ;; *) die "FarSight.xcodeproj sets SWIFT_COMPILATION_MODE to an unreviewed value" ;;
    esac ;;
  esac
  case " $(printf '%s ' $keys)" in *" INFOPLIST_FILE "*)
    [ "$(plutil -extract "objects.$id.buildSettings.INFOPLIST_FILE" raw -o - "$PROJECT/project.pbxproj")" = FarCast-Info.plist ] \
      || die "FarSight.xcodeproj's INFOPLIST_FILE is not FarCast-Info.plist, the one file this step reads"
    infoplists=$((infoplists + 1)) ;;
  esac
  for pair in SWIFT_VERSION=6.0 SWIFT_STRICT_CONCURRENCY=complete SWIFT_STRICT_MEMORY_SAFETY=YES SWIFT_TREAT_WARNINGS_AS_ERRORS=YES; do
    key=${pair%%=*}
    case " $(printf '%s ' $keys)" in *" $key "*)
      [ "$(plutil -extract "objects.$id.buildSettings.$key" raw -o - "$PROJECT/project.pbxproj")" = "${pair#*=}" ] \
        || die "FarSight.xcodeproj sets $key to something other than the literal ${pair#*=}"
      literals=$((literals + 1)) ;;
    esac
  done
done
[ "$literals" -eq 8 ] || die "FarSight.xcodeproj writes the four guardrails literally in $literals places, not in both of the target's configurations"
[ "$infoplists" -eq 2 ] || die "FarSight.xcodeproj names FarCast-Info.plist in $infoplists configurations, not in both of the target's"
# The one Info.plist file holds the build's commit and nothing else; every
# other key comes from a build setting reviewed above. The commit is passed
# at build time (FARCAST_COMMIT=…): without it the key is empty and the app
# reads nothing (ADR 0021 decision 9, amended 2026-11-12).
[ "$(plutil -convert json -o - "$APPLE/FarCast-Info.plist" 2>/dev/null)" = '{"FarCastCommit":"$(FARCAST_COMMIT)"}' ] \
  || die "farsight/client/apple/FarCast-Info.plist holds more or other than FarCastCommit = \$(FARCAST_COMMIT)"
# Every scheme anywhere — the pruned per-user folders and SwiftPM's .swiftpm
# included, since xcodebuild prefers a scheme it finds there to the one it
# would generate.
SCHEMES=$(find "$APPLE" \( -path "$APPLE/.build" -o -path "$KIT/.build" \) -prune -o -name '*.xcscheme' -print)
[ "$SCHEMES" = "$PROJECT/xcshareddata/xcschemes/FarCast.xcscheme" ] || die "the Apple client has schemes other than FarCast.xcscheme: $SCHEMES"
if grep -qE 'PreActions|PostActions|ExecutionAction|TestPlans|CommandLineArguments|EnvironmentVariables' "$SCHEMES" \
  || grep -oE 'buildConfiguration = "[^"]*"' "$SCHEMES" | grep -vqE '"(Debug|Release)"'; then
  die "FarCast.xcscheme runs actions, sets arguments or variables, or names a configuration other than Debug and Release"
fi
checked=0
for config in Debug Release; do
  for sdk in macosx iphoneos iphonesimulator xros xrsimulator; do
    xcodebuild -showBuildSettings -project "$PROJECT" -scheme FarCast -configuration "$config" -sdk "$sdk" >"$TMP/settings.txt" 2>&1 \
      || { tail -n 20 "$TMP/settings.txt" >&2; die "xcodebuild -showBuildSettings ($config, $sdk) failed"; }
    [ "$(grep -c '^Build settings for action build and target ' "$TMP/settings.txt")" = 1 ] \
      || die "FarCast ($config, $sdk): expected the settings of exactly one target"
    setting() { awk -v k="$1" '$1 == k && $2 == "=" { $1 = ""; $2 = ""; sub(/^ +/, ""); print; exit }' "$TMP/settings.txt"; }
    case "$(setting SWIFT_VERSION)" in 6|6.*) ;; *) die "FarCast ($config, $sdk): SWIFT_VERSION is '$(setting SWIFT_VERSION)', not 6" ;; esac
    [ "$(setting SWIFT_STRICT_CONCURRENCY)" = complete ] || die "FarCast ($config, $sdk): SWIFT_STRICT_CONCURRENCY is not complete"
    [ "$(setting SWIFT_STRICT_MEMORY_SAFETY)" = YES ] || die "FarCast ($config, $sdk): SWIFT_STRICT_MEMORY_SAFETY is not YES"
    [ "$(setting SWIFT_TREAT_WARNINGS_AS_ERRORS)" = YES ] || die "FarCast ($config, $sdk): SWIFT_TREAT_WARNINGS_AS_ERRORS is not YES"
    [ "$(setting SWIFT_SUPPRESS_WARNINGS)" != YES ] || die "FarCast ($config, $sdk): SWIFT_SUPPRESS_WARNINGS is YES"
    [ -z "$(setting OTHER_SWIFT_FLAGS)" ] || die "FarCast ($config, $sdk): OTHER_SWIFT_FLAGS is '$(setting OTHER_SWIFT_FLAGS)', which could switch a guardrail off"
    [ "$(setting INFOPLIST_FILE)" = FarCast-Info.plist ] || die "FarCast ($config, $sdk): INFOPLIST_FILE is '$(setting INFOPLIST_FILE)'"
    # Unset is the toolchain's default for the configuration.
    case "$(setting SWIFT_OPTIMIZATION_LEVEL)" in ''|-Onone|-O|-Osize) ;; *) die "FarCast ($config, $sdk): SWIFT_OPTIMIZATION_LEVEL is '$(setting SWIFT_OPTIMIZATION_LEVEL)'" ;; esac
    checked=$((checked + 1))
  done
done
ok "FarCast: the project has its reviewed shape, keys and scheme, and the guardrails are in effect in all $checked configuration and SDK pairs, and the one Info.plist holds only the build's commit"

xcode() {
  local log=$1; shift
  if ! xcodebuild "$@" -project "$PROJECT" -scheme FarCast -derivedDataPath "$DERIVED" >"$TMP/$log.log" 2>&1 9>&-; then
    grep -E 'error:|warning:|failed' "$TMP/$log.log" | sort -u | head -n 40 >&2 || tail -n 40 "$TMP/$log.log" >&2 || true
    die "xcodebuild $* failed (log above, abridged)"
  fi
}

step "7b — swift build and swift test (FarSightKit)"
# A full build, never -typecheck: region-isolation races surface in SIL.
if ! (cd "$KIT" && swift build --build-tests >"$TMP/swift-build.log" 2>&1); then
  { grep -E 'error:|warning:' "$TMP/swift-build.log" | sort -u | head -n 40 || tail -n 40 "$TMP/swift-build.log"; } >&2 || true
  die "swift build failed"
fi
ok "swift build"
# ADR 0020's Apple regression (ADR 0021 Verification 1): Go servers built
# from the PKI vectors and FatLine's own ServerTLSConfig, on 127.0.0.1, up
# for every test run below (fatline/internal/crypto/applefixture_test.go).
# The test binary is compiled and run directly, because go test hands a test
# binary an empty stdin, and its stdin is the server's lifeline.
go test -mod=vendor -c -o "$TMP/applefixture.test" ./fatline/internal/crypto/
mkfifo "$TMP/applefixture.in"
# Run from the package directory: the binary reads testdata/pki relative to it.
# exec, so $! is the test binary's own PID and fixture_stop's kill reaches it.
( cd "$ROOT/fatline/internal/crypto" && exec env FARCAST_APPLE_FIXTURE="$TMP/applefixture.json" \
    "$TMP/applefixture.test" -test.run '^TestServeAppleFixture$' -test.timeout 2h ) \
  <"$TMP/applefixture.in" >"$TMP/applefixture.log" 2>&1 &
FIXTURE_PID=$!
exec 9>"$TMP/applefixture.in"  # held open: its close is the server's signal to stop
# From here to fixture_stop, a long-running command starts with 9>&- (above).
for ((i = 0; i < 100; i++)); do
  [ -s "$TMP/applefixture.json" ] && break
  kill -0 "$FIXTURE_PID" 2>/dev/null || break
  sleep 0.1
done
[ -s "$TMP/applefixture.json" ] || { tail -n 20 "$TMP/applefixture.log" >&2; die "the Apple regression's Go server did not start"; }
fixture_addr() { local a; a=$(plutil -extract "$1" raw -o - "$TMP/applefixture.json" 2>/dev/null) && [[ $a =~ ^127\.0\.0\.1:[0-9]+$ ]] && printf '%s' "$a"; }
TLS_P256=$(fixture_addr p256) && TLS_FOREIGN=$(fixture_addr foreign) && TLS_ED25519=$(fixture_addr ed25519) \
  || die "the Apple regression's Go server wrote unexpected addresses"
ok "the Apple regression's Go servers listen on 127.0.0.1 (P-256, another CA, Ed25519)"
# The addresses reach the test commands only.
if ! (cd "$KIT" && FARSIGHT_TLS_P256="$TLS_P256" FARSIGHT_TLS_FOREIGN="$TLS_FOREIGN" FARSIGHT_TLS_ED25519="$TLS_ED25519" \
  swift test >"$TMP/swift-test.log" 2>&1) 9>&-; then
  { grep -E 'error|✘|failed' "$TMP/swift-test.log" | head -n 40 || tail -n 40 "$TMP/swift-test.log"; } >&2 || true
  tail -n 20 "$TMP/applefixture.log" >&2 || true
  die "swift test failed"
fi
tests=$(counted "$TMP/swift-test.log")
[ "$tests" -gt 0 ] || die "swift test ran no tests"
live_passed "$TMP/swift-test.log" "swift test"
SWIFT_TESTS=$tests
ok "swift test: $tests tests, the $REGRESSION_LIVE ADR 0020 live tests passed by name among them"

step "7c — the app, built for every platform it ships on"
xcode build-macos build -destination 'platform=macOS'
ok "macOS"
xcode build-ios build -destination 'generic/platform=iOS Simulator'
ok "iOS simulator"
xcode build-visionos build -destination 'generic/platform=visionOS Simulator'
ok "visionOS simulator"

step "7d — xcodebuild test, on macOS and an iOS simulator"
# The tests live in FarSightKit; the app target has none of its own, and an
# app scheme cannot reach a local package's test targets from the command
# line. So the package's own scheme runs them, under xcodebuild, on each
# runtime — what swift test cannot do for iOS.
kit_test() {
  local log=$1; shift
  # xcodebuild hands TEST_RUNNER_ variables to the test runner, prefix stripped.
  if ! (cd "$KIT" && env TEST_RUNNER_FARSIGHT_TLS_P256="$TLS_P256" TEST_RUNNER_FARSIGHT_TLS_FOREIGN="$TLS_FOREIGN" \
    TEST_RUNNER_FARSIGHT_TLS_ED25519="$TLS_ED25519" \
    xcodebuild test -scheme FarSightKit-Package -derivedDataPath "$ROOT/$DERIVED" "$@") >"$TMP/$log.log" 2>&1; then
    { grep -E 'error:|✘|failed|FAILED' "$TMP/$log.log" | grep -v linkd | sort -u | head -n 40 || tail -n 40 "$TMP/$log.log"; } >&2 || true
    tail -n 20 "$TMP/applefixture.log" >&2 || true
    die "xcodebuild test $* failed (log above, abridged)"
  fi
  local n
  n=$(counted "$TMP/$log.log")
  # The same tests as swift test ran, every one: a scheme that skips some
  # must not pass as a smaller run.
  [ "$n" -eq "$SWIFT_TESTS" ] || die "xcodebuild test $* ran $n tests, not the $SWIFT_TESTS swift test ran"
  live_passed "$TMP/$log.log" "xcodebuild test $*"
  printf '%s\n' "$n"
}
# Assigned first: a failure inside $(...) must stop the check, not print a
# blank count. The $(...) shell closes descriptor 9 with exec: a 9>&- on the
# call would leave bash a saved copy of it in that shell.
tests=$(exec 9>&-; kit_test test-macos -destination 'platform=macOS')
ok "macOS: $tests tests"
# All of xcodebuild's output is read (no early exit), so it is never cut off
# mid-write; the first eligible iPhone wins.
(cd "$KIT" && xcodebuild -showdestinations -scheme FarSightKit-Package >"$TMP/destinations.txt" 2>&1) 9>&- \
  || { tail -n 20 "$TMP/destinations.txt" >&2; die "xcodebuild -showdestinations failed"; }
SIM=$(awk -F'id:' '/Ineligible destinations/ { done = 1 } !done && !found && /platform:iOS Simulator/ && /name:iPhone/ && !/placeholder/ { split($2, a, ","); print a[1]; found = 1 }' "$TMP/destinations.txt")
[ -n "$SIM" ] || die "no iPhone simulator that runs iOS 26 or later is installed to test on. Add one in Xcode (Settings › Components), then re-run."
tests=$(exec 9>&-; kit_test test-ios -destination "id=$SIM")
ok "iOS simulator $SIM: $tests tests"
fixture_stop
ok "the ADR 0020 live tests passed by name on macOS and the iOS simulator; the Go servers are stopped"

# ---- 8. model --------------------------------------------------------------------
MODELNOTE="model: not run (--model)"
if [ -n "$MODEL" ]; then
  step "8 — the randomized hand-over model"
  FARCAST_MODEL=1 go test -mod=vendor -count=1 -timeout 30m -run '^TestHandOverModel' ./farsight/cli/internal/cli/
  ok "the model passes"
  MODELNOTE="model: passed"
fi

STEP="(done)"
printf '\n%scheck passed: root + sdk/go + Apple client · %s · %s · %s vendored modules · Swift %s · %s%s\n' \
  "$GRN$BOLD" "$GOV" "$(printf '%s' "$LINT" | awk '{print "golangci-lint " $4}')" "$vendored" "$SWIFTV" "$MODELNOTE" "$RST"
