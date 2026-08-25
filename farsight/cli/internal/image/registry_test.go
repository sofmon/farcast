package image

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/oci"
)

// testRegistry is a small in-memory registry over httptest — enough for the
// builder to pull a base from and push an image to, with no network and no
// cloud account (cloud-touching tests are integration-gated and never run in
// CI, per the cost pillar).
type testRegistry struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string]manifestEntry
	sawAuth   bool

	requireAuth bool
	user, pass  string
}

type manifestEntry struct {
	body      []byte
	mediaType string
}

func newTestRegistry(t *testing.T) *testRegistry {
	t.Helper()
	r := &testRegistry{
		t:         t,
		blobs:     map[string][]byte{},
		manifests: map[string]manifestEntry{},
	}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *testRegistry) host() string { return strings.TrimPrefix(r.srv.URL, "http://") }

func (r *testRegistry) sawCredentials() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sawAuth
}

func (r *testRegistry) serve(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Authorization") != "" {
		r.mu.Lock()
		r.sawAuth = true
		r.mu.Unlock()
	}
	if r.requireAuth {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(r.user+":"+r.pass))
		if req.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Basic realm="fake"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	path := strings.TrimPrefix(req.URL.Path, "/v2/")
	switch {
	case strings.Contains(path, "/manifests/"):
		repo, id, _ := strings.Cut(path, "/manifests/")
		r.serveManifest(w, req, repo, id)
	case strings.Contains(path, "/blobs/uploads"):
		repo, _, _ := strings.Cut(path, "/blobs/uploads")
		r.serveUpload(w, req, repo)
	case strings.Contains(path, "/blobs/"):
		repo, digest, _ := strings.Cut(path, "/blobs/")
		r.serveBlob(w, req, repo, digest)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (r *testRegistry) serveManifest(w http.ResponseWriter, req *http.Request, repo, id string) {
	if req.Method == http.MethodPut {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			r.t.Fatalf("read manifest body: %v", err)
		}
		digest := sha256Ref(body)
		r.mu.Lock()
		entry := manifestEntry{body: body, mediaType: req.Header.Get("Content-Type")}
		r.manifests[repo+":"+id] = entry
		r.manifests[repo+":"+digest] = entry
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
		return
	}
	r.mu.Lock()
	entry, ok := r.manifests[repo+":"+id]
	r.mu.Unlock()
	if !ok {
		http.Error(w, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", entry.mediaType)
	w.Header().Set("Docker-Content-Digest", sha256Ref(entry.body))
	w.Header().Set("Content-Length", fmt.Sprint(len(entry.body)))
	if req.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(entry.body)
}

func (r *testRegistry) serveBlob(w http.ResponseWriter, req *http.Request, repo, digest string) {
	r.mu.Lock()
	blob, ok := r.blobs[repo+"@"+digest]
	r.mu.Unlock()
	if !ok {
		http.Error(w, `{"errors":[{"code":"BLOB_UNKNOWN"}]}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(blob)))
	if req.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(blob)
}

func (r *testRegistry) serveUpload(w http.ResponseWriter, req *http.Request, repo string) {
	switch req.Method {
	case http.MethodPost:
		w.Header().Set("Location", "/v2/"+repo+"/blobs/uploads/session")
		w.WriteHeader(http.StatusAccepted)
	case http.MethodPut:
		body, err := io.ReadAll(req.Body)
		if err != nil {
			r.t.Fatalf("read blob body: %v", err)
		}
		digest := req.URL.Query().Get("digest")
		if got := sha256Ref(body); got != digest {
			http.Error(w, "digest mismatch", http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.blobs[repo+"@"+digest] = body
		r.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *testRegistry) addBlob(repo string, blob []byte) oci.Descriptor {
	digest := sha256Ref(blob)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blobs[repo+"@"+digest] = blob
	return oci.Descriptor{Digest: digest, Size: int64(len(blob))}
}

func (r *testRegistry) blob(repo, digest string) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.blobs[repo+"@"+digest]
}

func (r *testRegistry) manifest(repo, id string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.manifests[repo+":"+id]
	return entry.body, ok
}

// seedBase publishes a two-platform index standing in for the pinned distroless
// base, and returns a reference pinned to the index digest.
func seedBase(t *testing.T, r *testRegistry, repo, tag string) string {
	t.Helper()
	var entries []oci.Descriptor
	for _, arch := range []string{"amd64", "arm64"} {
		layer, err := oci.BuildLayer([]oci.File{{Path: "/base", Mode: 0o644, Data: []byte("base " + arch)}})
		if err != nil {
			t.Fatal(err)
		}
		layerDesc := r.addBlob(repo, layer.Blob)
		layerDesc.MediaType = oci.MediaTypeOCILayerGzip

		cfg := []byte(`{"created":"2020-01-01T00:00:00Z","architecture":"` + arch + `","os":"linux",` +
			`"config":{"Env":["PATH=/usr/local/bin"],"User":"65532:65532","Cmd":["/base-default"]},` +
			`"rootfs":{"type":"layers","diff_ids":["` + layer.DiffID + `"]},` +
			`"history":[{"created":"2020-01-01T00:00:00Z","created_by":"base"}]}`)
		cfgDesc := r.addBlob(repo, cfg)
		cfgDesc.MediaType = oci.MediaTypeOCIConfig

		body, err := json.Marshal(oci.Manifest{
			SchemaVersion: 2,
			MediaType:     oci.MediaTypeOCIManifest,
			Config:        cfgDesc,
			Layers:        []oci.Descriptor{layerDesc},
		})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256Ref(body)
		r.mu.Lock()
		r.manifests[repo+":"+digest] = manifestEntry{body: body, mediaType: oci.MediaTypeOCIManifest}
		r.mu.Unlock()
		entries = append(entries, oci.Descriptor{
			MediaType: oci.MediaTypeOCIManifest,
			Digest:    digest,
			Size:      int64(len(body)),
			Platform:  &oci.Platform{OS: "linux", Architecture: arch},
		})
	}
	index, err := json.Marshal(oci.Index{SchemaVersion: 2, MediaType: oci.MediaTypeOCIIndex, Manifests: entries})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Ref(index)
	r.mu.Lock()
	entry := manifestEntry{body: index, mediaType: oci.MediaTypeOCIIndex}
	r.manifests[repo+":"+tag] = entry
	r.manifests[repo+":"+digest] = entry
	r.mu.Unlock()
	return r.host() + "/" + repo + ":" + tag + "@" + digest
}
