package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	pfetch "github.com/sofmon/farcast/planck/fetch"
)

// fetchTimeout bounds how long the CLI waits for a manifest read. The Job
// carries its own, shorter deadline; this is the operator's patience.
const fetchTimeout = 8 * time.Minute

// fetched is a manifest, read inside the instance, with the two facts that
// make it checkable afterwards.
type fetched struct {
	Manifest []byte
	Report   pfetch.Report
	Job      string
}

// readManifest runs the fetch Job and returns what it read.
//
// The manifest arrives on the Job's stdout and the commit and digest arrive in
// the Pod's termination message. Two channels, and the caller checks one
// against the other — see Report.Verify for exactly what that does and does
// not prove.
func readManifest(ctx context.Context, env *Env, cl jobWaiter, cfg pfetch.Config) (fetched, error) {
	manifest, err := pfetch.Render(cfg)
	if err != nil {
		return fetched{}, err
	}
	if err := cl.Apply(ctx, manifest); err != nil {
		return fetched{}, fmt.Errorf("start the manifest read: %w", err)
	}

	job := cfg.Job()
	if isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Reading %s inside %q — the instance clones it, not this machine.\n",
			cfg.Repo, cfg.Instance)
	}

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
		return fetched{}, fmt.Errorf("could not read %s from %s; its Job survives for %d minutes so "+
			"'kubectl -n %s logs job/%s' still works",
			cfg.Manifest, cfg.Repo, pfetch.TTLSeconds/60, pfetch.Namespace, job)
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
		// kubectl adds nothing to a single container's log, but a Pod that
		// restarted or a log that rotated would. Try once without the
		// trailing newline the shell's own `cat` may not have produced.
		if trimmed := strings.TrimSuffix(logs, "\n"); report.Verify([]byte(trimmed)) == nil {
			raw = []byte(trimmed)
		} else {
			return fetched{}, err
		}
	}
	return fetched{Manifest: raw, Report: report, Job: job}, nil
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
