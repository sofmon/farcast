package kubetest

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// logs is GET …/pods/<p>/log. It honours container, tailLines, follow and
// previous:
//   - container names one of the pod's containers; without it, a pod with one
//     regular container reads that one, and any other pod answers 400, as the
//     API server's pod log location does [a port from memory, not fetched, of
//     kubernetes v1.37.2 pkg/registry/core/pod/strategy.go, LogLocation];
//   - tailLines is a non-negative integer, the number of last lines; a
//     negative or non-integer value answers 400, and no parameter is
//     everything;
//   - previous=true reads the previous instance's log, and answers 400 for a
//     container with no previous instance;
//   - follow=true keeps the stream open, after the log, until the request's
//     context ends (the client goes, or Close).
//
// The body is text/plain, chunked, with each line flushed as it is written.
// A container's log is its pod's LogAnnotationPrefix annotation, and its
// previous instance's the PreviousLogAnnotationPrefix one.
func (s *Server) logs(w http.ResponseWriter, r *http.Request, ri requestInfo, k kube.Kind) {
	q := r.URL.Query()
	tail := -1
	if q.Has("tailLines") {
		v := q.Get("tailLines")
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			badRequest(w, "tailLines %q is not a non-negative integer", v)
			return
		}
		tail = n
	}
	follow, ok := boolParam(w, q, "follow")
	if !ok {
		return
	}
	previous, ok := boolParam(w, q, "previous")
	if !ok {
		return
	}
	container := q.Get("container")

	s.mu.Lock()
	so := s.objects[k.Path(ri.namespace, ri.name)]
	var regular, all []string
	var text string
	var hasPrevious bool
	if so != nil {
		regular, all = containerNames(so.obj)
		if container == "" && len(regular) == 1 {
			container = regular[0]
		}
		ann, _ := metadataOf(so.obj)["annotations"].(map[string]any)
		if previous {
			text, hasPrevious = ann[PreviousLogAnnotationPrefix+container].(string)
		} else {
			text, _ = ann[LogAnnotationPrefix+container].(string)
		}
	}
	s.mu.Unlock()

	switch {
	case so == nil:
		notFound(w, k, ri.name)
		return
	case container == "" && len(regular) == 0:
		badRequest(w, "a container name must be specified for pod %s", ri.name)
		return
	case container == "":
		badRequest(w, "a container name must be specified for pod %s, choose one of: [%s]", ri.name, strings.Join(regular, " "))
		return
	case !slices.Contains(all, container):
		badRequest(w, "container %s is not valid for pod %s", container, ri.name)
		return
	case previous && !hasPrevious:
		badRequest(w, "previous terminated container %q in pod %q not found", container, ri.name)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}
	flush()
	for _, line := range lastLines(text, tail) {
		if _, err := w.Write([]byte(line)); err != nil {
			return
		}
		flush()
	}
	if follow {
		<-r.Context().Done()
	}
}

// boolParam reads an optional boolean parameter, answering 400 for a value
// that is not one.
func boolParam(w http.ResponseWriter, q url.Values, name string) (bool, bool) {
	if !q.Has(name) {
		return false, true
	}
	b, err := strconv.ParseBool(q.Get(name))
	if err != nil {
		badRequest(w, "%s %q is not a boolean", name, q.Get(name))
		return false, false
	}
	return b, true
}

// containerNames are a pod's regular containers, and all of its containers:
// regular, init and ephemeral.
func containerNames(pod map[string]any) (regular, all []string) {
	spec, _ := pod["spec"].(map[string]any)
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		list, _ := spec[field].([]any)
		for _, c := range list {
			m, _ := c.(map[string]any)
			name := str(m, "name")
			if name == "" {
				continue
			}
			if field == "containers" {
				regular = append(regular, name)
			}
			all = append(all, name)
		}
	}
	return regular, all
}

// lastLines splits a log into its lines, each with its own newline, and keeps
// the last n; n < 0 keeps them all.
func lastLines(text string, n int) []string {
	if text == "" {
		return nil
	}
	lines := strings.SplitAfter(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if n >= 0 && n < len(lines) {
		lines = lines[len(lines)-n:]
	}
	return lines
}
