package cli

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	pfetch "github.com/sofmon/farcast/planck/fetch"
)

// fetchTimeout bounds how long the CLI waits for a manifest read. The Job
// carries its own, shorter deadline; this is the operator's patience.
const fetchTimeout = 8 * time.Minute

// msgFetchFailed is a failed manifest read's error: the manifest and the
// repository. The end of the read's log, when JobLogs could read it, is
// printed above it.
const msgFetchFailed = "could not read %s from %s; the end of the read's log, when it could be read, is printed above"

// fetchDefaultRef is the ref the fetch reads when run is given no --ref, as
// planck/fetch defaults it (TestTheFetchDefaultsAreFetchs pins the two
// together). The manifest it reads when given no --manifest is
// pfetch.DefaultManifest.
const fetchDefaultRef = "refs/heads/main"

// fetched is a manifest, read inside the instance, with the two facts that
// make it checkable afterwards, and the fetch Job it was read from: its name,
// and its uid, which tells this Job from another of the same name (a Job's
// name is deterministic, ADR 0023 M2.6d, A23-47).
type fetched struct {
	Manifest []byte
	Report   pfetch.Report
	Job      string
	UID      string
}

// fetchReader is the slice of the cluster client that reads a fetch Job
// another call applied: its wait, which ends with the Job's uid, and its
// logs (A23-47). Under 'run --confirm' the reader reads the Job the writer
// applied.
type fetchReader interface {
	WaitJob(ctx context.Context, namespace, name string, timeout time.Duration) (cluster.JobResult, error)
	JobLogs(ctx context.Context, namespace, job string, lines int) (string, error)
}

// applyFetch renders the fetch Job and applies it, the first half of the
// manifest read: the instance clones the repository and prints the manifest
// it finds. readFetch is the second.
func applyFetch(ctx context.Context, env *Env, cl jobWaiter, cfg pfetch.Config) error {
	manifest, err := pfetch.Render(cfg)
	if err != nil {
		return err
	}
	if err := cl.Apply(ctx, manifest); err != nil {
		return fmt.Errorf("start the manifest read: %w", err)
	}
	if isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Reading %s inside %q — the instance clones it, not this machine.\n",
			cfg.Repo, cfg.Instance)
	}
	return nil
}

// readFetch waits for the fetch Job applyFetch applied and returns what it
// read, with the Job's uid.
//
// The manifest arrives on the Job's stdout and the commit and digest arrive in
// the Pod's termination message. Two channels, and the caller checks one
// against the other — see Report.Verify for exactly what that does and does
// not prove.
func readFetch(ctx context.Context, env *Env, cl fetchReader, cfg pfetch.Config) (fetched, error) {
	job := cfg.Job()
	res, err := cl.WaitJob(ctx, pfetch.Namespace, job, fetchTimeout)
	if err != nil {
		return fetched{}, fmt.Errorf("wait for the manifest read: %w", err)
	}
	if !res.Succeeded {
		// A fetch that could not find the manifest says so in its termination
		// message; one that could not clone says so in its logs. Both are the
		// operator's answer, and neither is improved by restating it.
		if msg := strings.TrimSpace(res.Message); msg != "" {
			return fetched{}, fmt.Errorf("reading %s: %s", cfg.Repo, msg)
		}
		if logs, lerr := cl.JobLogs(ctx, pfetch.Namespace, job, 40); lerr == nil && strings.TrimSpace(logs) != "" {
			fprintf(env.Err, "\n%s\n", strings.TrimRight(logs, "\n"))
		}
		return fetched{}, fmt.Errorf(msgFetchFailed, cfg.Manifest, cfg.Repo)
	}

	report, err := pfetch.ParseReport(res.Message)
	if err != nil {
		return fetched{}, err
	}

	// Everything, never a tail: the log IS the manifest, and a truncated one
	// parses perfectly with its first applications missing.
	logs, err := cl.JobLogs(ctx, pfetch.Namespace, job, 0)
	if err != nil {
		return fetched{}, fmt.Errorf("read the manifest the instance printed: %w", err)
	}
	raw := []byte(logs)
	if err := report.Verify(raw); err != nil {
		// The API adds nothing to a single container's log, but a Pod that
		// restarted or a log that rotated would. Try once without the
		// trailing newline the shell's own `cat` may not have produced.
		if trimmed := strings.TrimSuffix(logs, "\n"); report.Verify([]byte(trimmed)) == nil {
			raw = []byte(trimmed)
		} else {
			return fetched{}, err
		}
	}
	return fetched{Manifest: raw, Report: report, Job: job, UID: res.UID}, nil
}

// withoutUserinfo is a repository URL without a user name or credential in it,
// or s unchanged when it has none or is not a URL.
func withoutUserinfo(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	u.User = nil
	return u.String()
}

// repoURL normalises what an operator types.
//
// `farcast run github.com/user/repo` is the shape PLAN 4.3 promises, and it is
// the shape people actually paste. A scheme is added rather than demanded, and
// only https:// is ever produced: the fetch and the build both authenticate
// over it with the same read-only credential.
func repoURL(s string) (string, error) {
	s = strings.TrimSpace(strings.TrimRight(s, "/"))
	switch {
	case s == "":
		return "", usagef("run takes a repository, e.g. 'farcast run <instance> github.com/user/repo'")
	case strings.HasPrefix(s, "https://"):
		// A credential in the URL would be written into the fetch Job, which
		// the provider stores, and into this machine's record, which every
		// 'farcast world' prints. The message names the URL without it.
		if u, err := url.Parse(s); err == nil && u.User != nil {
			return "", usagef("refusing %q with a user name or credential in it; it would be written into the instance's fetch Job "+
				"and this machine's record. Name the repository without it, and pass a read-only credential with --git-secret",
				withoutUserinfo(s))
		}
		return s, nil
	case strings.HasPrefix(s, "http://"):
		return "", usagef("refusing http:// for %q; the source of what an instance is about to run is not carried in clear", s)
	case strings.HasPrefix(s, "git://"), strings.HasPrefix(s, "ssh://"), strings.Contains(s, "@"):
		return "", usagef("%q is not an https:// repository; the instance clones with git over HTTPS "+
			"and authenticates with a read-only credential, so ssh and git:// have no way in", s)
	case strings.HasPrefix(s, "/"), strings.HasPrefix(s, "."):
		return "", usagef("%q is a local path; the instance clones the repository itself, which is what "+
			"makes deploying independent of this machine (ADR 0010)", s)
	}
	if !strings.Contains(s, "/") || !strings.Contains(strings.SplitN(s, "/", 2)[0], ".") {
		return "", usagef("%q does not look like a repository; expected something like github.com/user/repo", s)
	}
	return "https://" + s, nil
}
