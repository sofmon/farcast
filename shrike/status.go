package shrike

import (
	"encoding/json"
	"net/http"
)

// StatusPath is the route the Monitor's status handler serves the security
// picture on.
const StatusPath = "/_shrike/status"

// Handler returns an http.Handler that serves the live Snapshot as JSON at
// StatusPath. It exposes only host/port metadata and decision counts — never
// payload or secrets, which the event stream carries none of by construction.
func (m *Monitor) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(StatusPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m.Snapshot())
	})
	return mux
}
