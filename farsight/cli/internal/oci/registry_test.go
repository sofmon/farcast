package oci

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
)

// authMode selects how the fake registry challenges a client.
type authMode int

const (
	authNone authMode = iota
	authBasic
	authBearer
)

// fakeRegistry is an in-memory OCI registry over httptest: enough of the
// protocol to exercise the client's pull, push, and authentication paths
// without a network or a cloud account (the cost pillar keeps cloud-touching
// tests out of CI entirely).
type fakeRegistry struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	blobs     map[string][]byte // "repo@digest" -> bytes
	manifests map[string]stored // "repo:identifier" -> manifest
	uploads   map[string][]byte
	requests  []string
	sawAuth   bool // any request arrived carrying an Authorization header

	mode             authMode
	user, pass       string
	token            string
	tokenRealm       string // overrides the realm advertised in a Bearer challenge
	omitDigestHeader bool
	putDigestLie     string          // if set, the digest a manifest PUT claims to have stored
	corrupt          map[string]bool // digests to serve with flipped bytes
}

type stored struct {
	body      []byte
	mediaType string
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	r := &fakeRegistry{
		t:         t,
		blobs:     map[string][]byte{},
		manifests: map[string]stored{},
		uploads:   map[string][]byte{},
		corrupt:   map[string]bool{},
		token:     "fake-bearer-token",
	}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

// host returns the registry host as it appears in an image reference. It is a
// loopback address, which is why the client talks to it over plain HTTP.
func (r *fakeRegistry) host() string { return strings.TrimPrefix(r.srv.URL, "http://") }

func (r *fakeRegistry) log(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req.Method+" "+req.URL.Path)
	if req.Header.Get("Authorization") != "" {
		r.sawAuth = true
	}
}

func (r *fakeRegistry) sawCredentials() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sawAuth
}

func (r *fakeRegistry) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.requests...)
}

func (r *fakeRegistry) countCalls(prefix string) int {
	n := 0
	for _, c := range r.calls() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (r *fakeRegistry) serve(w http.ResponseWriter, req *http.Request) {
	r.log(req)
	if req.URL.Path == "/token" {
		r.serveToken(w, req)
		return
	}
	if !r.authorized(w, req) {
		return
	}
	repo, kind, rest, ok := splitV2Path(req.URL.Path)
	if !ok {
		http.Error(w, "not a v2 path", http.StatusNotFound)
		return
	}
	switch {
	case kind == "manifests":
		r.serveManifest(w, req, repo, rest)
	case kind == "blobs" && strings.HasPrefix(rest, "uploads"):
		r.serveUpload(w, req, repo, strings.TrimPrefix(strings.TrimPrefix(rest, "uploads"), "/"))
	case kind == "blobs":
		r.serveBlob(w, req, repo, rest)
	default:
		http.Error(w, "unhandled", http.StatusNotFound)
	}
}

func (r *fakeRegistry) serveToken(w http.ResponseWriter, req *http.Request) {
	if r.user != "" {
		u, p, ok := req.BasicAuth()
		if !ok || u != r.user || p != r.pass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	if req.URL.Query().Get("scope") == "" {
		r.t.Errorf("token request carried no scope: %s", req.URL)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": r.token})
}

// authorized enforces the configured challenge, writing the 401 when the
// request does not satisfy it.
func (r *fakeRegistry) authorized(w http.ResponseWriter, req *http.Request) bool {
	switch r.mode {
	case authNone:
		return true
	case authBasic:
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(r.user+":"+r.pass))
		if req.Header.Get("Authorization") == want {
			return true
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="fake"`)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	default:
		if req.Header.Get("Authorization") == "Bearer "+r.token {
			return true
		}
		realm := r.tokenRealm
		if realm == "" {
			realm = r.srv.URL + "/token"
		}
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer realm=%q,service="fake",scope="repository:x:pull"`, realm))
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
}

func (r *fakeRegistry) serveManifest(w http.ResponseWriter, req *http.Request, repo, id string) {
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		r.mu.Lock()
		m, ok := r.manifests[repo+":"+id]
		r.mu.Unlock()
		if !ok {
			http.Error(w, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", m.mediaType)
		if !r.omitDigestHeader {
			w.Header().Set("Docker-Content-Digest", digestOf(m.body))
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(m.body)))
		if req.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(m.body)
	case http.MethodPut:
		body := readAll(r.t, req)
		digest := digestOf(body)
		r.mu.Lock()
		r.manifests[repo+":"+id] = stored{body: body, mediaType: req.Header.Get("Content-Type")}
		r.manifests[repo+":"+digest] = stored{body: body, mediaType: req.Header.Get("Content-Type")}
		lie := r.putDigestLie
		r.mu.Unlock()
		if lie != "" {
			digest = lie
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *fakeRegistry) serveBlob(w http.ResponseWriter, req *http.Request, repo, digest string) {
	r.mu.Lock()
	blob, ok := r.blobs[repo+"@"+digest]
	corrupt := r.corrupt[digest]
	r.mu.Unlock()
	if !ok {
		http.Error(w, `{"errors":[{"code":"BLOB_UNKNOWN"}]}`, http.StatusNotFound)
		return
	}
	if corrupt {
		// Same length, different content: the size check must not be what
		// catches this — the digest must.
		tampered := append([]byte(nil), blob...)
		tampered[len(tampered)-1] ^= 0xff
		blob = tampered
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(blob)))
	if req.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(blob)
}

func (r *fakeRegistry) serveUpload(w http.ResponseWriter, req *http.Request, repo, id string) {
	switch req.Method {
	case http.MethodPost:
		r.mu.Lock()
		session := fmt.Sprintf("u%d", len(r.uploads)+1)
		r.uploads[session] = nil
		r.mu.Unlock()
		// A relative Location carrying opaque session state, as real
		// registries emit.
		w.Header().Set("Location", "/v2/"+repo+"/blobs/uploads/"+session+"?_state=abc%2Fdef")
		w.WriteHeader(http.StatusAccepted)
	case http.MethodPut:
		if req.URL.Query().Get("_state") != "abc/def" {
			r.t.Errorf("upload session state was mangled: %q", req.URL.RawQuery)
		}
		digest := req.URL.Query().Get("digest")
		body := readAll(r.t, req)
		if got := digestOf(body); got != digest {
			http.Error(w, "digest mismatch", http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.blobs[repo+"@"+digest] = body
		delete(r.uploads, id)
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func readAll(t *testing.T, req *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	return body
}

// splitV2Path splits "/v2/<repo>/<kind>/<rest>", where the repository itself
// may contain slashes.
func splitV2Path(p string) (repo, kind, rest string, ok bool) {
	if !strings.HasPrefix(p, "/v2/") {
		return "", "", "", false
	}
	p = strings.TrimPrefix(p, "/v2/")
	for _, k := range []string{"manifests", "blobs"} {
		marker := "/" + k + "/"
		if i := strings.Index(p, marker); i >= 0 {
			return p[:i], k, p[i+len(marker):], true
		}
	}
	return "", "", "", false
}

// --- seeding helpers -------------------------------------------------------

func (r *fakeRegistry) addBlob(repo string, blob []byte) Descriptor {
	digest := digestOf(blob)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blobs[repo+"@"+digest] = blob
	return Descriptor{Digest: digest, Size: int64(len(blob))}
}

func (r *fakeRegistry) addManifest(repo, id string, body []byte, mediaType string) string {
	digest := digestOf(body)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[repo+":"+id] = stored{body: body, mediaType: mediaType}
	r.manifests[repo+":"+digest] = stored{body: body, mediaType: mediaType}
	return digest
}

func (r *fakeRegistry) hasBlob(repo, digest string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.blobs[repo+"@"+digest]
	return ok
}

// baseConfigJSON is a stand-in for the distroless config: it carries fields
// this package models and fields it does not, so the round trip can be asserted
// to preserve the latter.
func baseConfigJSON(diffID string) []byte {
	return []byte(`{
  "created": "2020-01-01T00:00:00Z",
  "architecture": "amd64",
  "os": "linux",
  "config": {
    "Env": ["PATH=/usr/local/bin", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"],
    "User": "65532:65532",
    "Cmd": ["/base-default"],
    "WorkingDir": "/"
  },
  "rootfs": {"type": "layers", "diff_ids": ["` + diffID + `"]},
  "history": [{"created": "2020-01-01T00:00:00Z", "created_by": "base"}],
  "vendor.extension": {"keep": true, "count": 42}
}`)
}

// seedIndexedImage publishes a two-platform index at repo:tag, backed by a real
// layer, config, and manifest for each platform. It returns the index digest
// and the amd64 manifest digest.
func seedIndexedImage(t *testing.T, r *fakeRegistry, repo, tag string) (indexDigest, amd64Digest string) {
	t.Helper()
	var entries []Descriptor
	for _, plat := range []Platform{{OS: "linux", Architecture: "amd64"}, {OS: "linux", Architecture: "arm64"}} {
		layer, err := BuildLayer([]File{{Path: "/base-" + plat.Architecture, Mode: 0o644, Data: []byte("base content " + plat.Architecture)}})
		if err != nil {
			t.Fatalf("build base layer: %v", err)
		}
		layerDesc := r.addBlob(repo, layer.Blob)
		layerDesc.MediaType = MediaTypeOCILayerGzip

		cfg := baseConfigJSON(layer.DiffID)
		cfgDesc := r.addBlob(repo, cfg)
		cfgDesc.MediaType = MediaTypeOCIConfig

		manifest, err := json.Marshal(Manifest{
			SchemaVersion: 2,
			MediaType:     MediaTypeOCIManifest,
			Config:        cfgDesc,
			Layers:        []Descriptor{layerDesc},
		})
		if err != nil {
			t.Fatalf("marshal base manifest: %v", err)
		}
		digest := r.addManifest(repo, digestOf(manifest), manifest, MediaTypeOCIManifest)
		if plat.Architecture == "amd64" {
			amd64Digest = digest
		}
		entries = append(entries, Descriptor{
			MediaType: MediaTypeOCIManifest,
			Digest:    digest,
			Size:      int64(len(manifest)),
			Platform:  &Platform{OS: plat.OS, Architecture: plat.Architecture},
		})
	}
	index, err := json.Marshal(Index{SchemaVersion: 2, MediaType: MediaTypeOCIIndex, Manifests: entries})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	indexDigest = r.addManifest(repo, tag, index, MediaTypeOCIIndex)
	return indexDigest, amd64Digest
}
