package fetch

import "strings"

// script is what the fetch container runs.
//
// It is a constant. Every value that varies — the repository, the ref, the
// manifest path, the credential — reaches it as an environment variable, so
// nothing an operator types is ever concatenated into shell text.
const script = `set -eu

# Everything git writes goes to the workspace volume: the root filesystem is
# read-only, and what a clone leaves behind should die with the Pod.
export HOME="{{WORKDIR}}"
cd "$HOME"

if [ -n "${GIT_USERNAME:-}" ]; then
  # An askpass helper rather than a credential in the URL. A token in the URL
  # would have to be URL-encoded to survive a "/" or an "@", would appear in
  # git's own error messages, and would be visible in the process table.
  printf '#!/bin/sh\ncase "$1" in\nUsername*) printf %%s "$GIT_USERNAME" ;;\n*) printf %%s "$GIT_PASSWORD" ;;\nesac\n' > "$HOME/askpass"
  chmod 700 "$HOME/askpass"
  GIT_ASKPASS="$HOME/askpass"
  export GIT_ASKPASS
fi

# Never block on a prompt nobody is there to answer: a private repository with
# no credential should fail in seconds, not hold the Job until its deadline.
export GIT_TERMINAL_PROMPT=0

# init + fetch rather than clone. "git clone --branch" takes a branch or a tag
# and refuses a commit SHA, while "git fetch origin <ref>" accepts all three —
# and a commit SHA is exactly what a re-read of an already-approved tree uses.
git init --quiet "$HOME/src"
git -C "$HOME/src" remote add origin "$FARCAST_REPO"
git -C "$HOME/src" fetch --quiet --depth 1 origin "$FARCAST_REF"
git -C "$HOME/src" checkout --quiet FETCH_HEAD

commit=$(git -C "$HOME/src" rev-parse HEAD)
path="$HOME/src/$FARCAST_MANIFEST"
if [ ! -f "$path" ]; then
  printf 'no %s at %s in %s\n' "$FARCAST_MANIFEST" "$commit" "$FARCAST_REPO" > {{REPORT}}
  exit 1
fi

# The report goes to the termination message and the manifest goes to stdout.
# Two channels on purpose: the caller reads the manifest from the log and
# checks it against a digest that did not travel the same way, which is what
# catches a truncated log rather than trusting one.
digest=$(sha256sum "$path" | cut -d' ' -f1)
printf 'commit=%s manifest=sha256:%s\n' "$commit" "$digest" > {{REPORT}}
cat "$path"
`

// scriptFor fills the script's two structural placeholders. They are the
// workspace path and the report path — locations this package owns, never
// anything the operator supplied.
func scriptFor(workDir, reportFile string) string {
	return strings.NewReplacer(
		"{{WORKDIR}}", workDir,
		"{{REPORT}}", reportFile,
	).Replace(script)
}
