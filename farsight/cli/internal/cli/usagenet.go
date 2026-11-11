package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/shrike"
)

// networkTimeout bounds reading the monitor's picture. It is short: the whole
// point of the network section is that it never delays the compute one.
const networkTimeout = 15 * time.Second

// streamDialer opens a relayed stream to a named in-instance service. It is an
// interface so the report can be tested without a cluster.
type streamDialer interface {
	DialStream(ctx context.Context, route string, ordinal int) (net.Conn, error)
}

// instanceTunnel opens the operator's mTLS tunnel to an instance.
//
// The error is returned plain. Every caller wants different advice attached to
// it — an unreachable tunnel means storage cannot be unsealed, and it means
// the network half of a usage report is missing — and prose belongs where the
// consequence is known.
func instanceTunnel(ctx context.Context, env *Env, name string) (*tunnel.Conn, config.MTLSMaterial, error) {
	var mtls config.MTLSMaterial
	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return nil, mtls, fmt.Errorf("load instance %q: %w", name, err)
	}
	if meta.Carrier == nil || meta.Carrier.Endpoint == "" {
		return nil, mtls, fmt.Errorf("instance %q has no tunnel; run 'farcast connect %s' first", name, name)
	}
	if mtls, err = env.ConfigDir.LoadInstanceMTLS(name); err != nil {
		return nil, mtls, fmt.Errorf("load the mTLS identity for %q: %w", name, err)
	}
	id, err := clientIdentity(mtls, name)
	if err != nil {
		return nil, mtls, err
	}
	conn, err := tunnel.Connect(ctx, "https://"+meta.Carrier.Endpoint, id)
	if err != nil {
		return nil, mtls, err
	}
	return conn, mtls, nil
}

// fetchNetwork reads Shrike's live picture through the tunnel.
//
// Plain HTTP over the relayed stream, with no second TLS leg — unlike the
// keyholder, which speaks mTLS inside the relay. The difference is what is at
// stake on each hop: the keyholder's protects key material against something
// the cloud could stand up in its place, while this stream ends on the
// loopback of the very Pod that relayed it, and carries decision counts. Who
// reaches it is settled by the tunnel: it admits only the operator and the
// instance's keeper devices, and this route is the operator's alone.
func fetchNetwork(ctx context.Context, d streamDialer) (shrike.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, networkTimeout)
	defer cancel()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialStream(ctx, fldeploy.ShrikeStreamRoute, -1)
		},
		DisableKeepAlives: true,
	}}
	url := fmt.Sprintf("http://127.0.0.1:%d%s", fldeploy.ShrikeStatusPort, shrike.StatusPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return shrike.Snapshot{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return shrike.Snapshot{}, fmt.Errorf("reaching the monitor: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return shrike.Snapshot{}, fmt.Errorf("the monitor answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return shrike.Snapshot{}, fmt.Errorf("reading the monitor's picture: %w", err)
	}
	var snap shrike.Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return shrike.Snapshot{}, fmt.Errorf("decoding the monitor's picture: %w", err)
	}
	return snap, nil
}

// tunnelRow is one tunnel peer's use of one route, with the peer named as far
// as THIS machine can name it.
type tunnelRow struct {
	// Who is the peer as the operator reads it: "operator", "keeper <device>",
	// or why it cannot be named from here.
	Who string `json:"who"`
	// Role is FatLine's own classification; Peer the opaque leaf token the
	// monitor recorded. Kept beside Who so a row this machine could not name
	// can be matched against the machine that enrolled the device.
	Role      string           `json:"role,omitempty"`
	Peer      string           `json:"peer,omitempty"`
	Route     string           `json:"route"`
	Relayed   int64            `json:"relayed"`
	Refused   int64            `json:"refused"`
	Reasons   map[string]int64 `json:"reasons,omitempty"`
	Failed    int64            `json:"failed"`
	BytesUp   int64            `json:"bytes_up"`
	BytesDown int64            `json:"bytes_down"`
	LastSeen  time.Time        `json:"last_seen,omitzero"`
}

// attributeTunnel names each tunnel row's peer from this machine's records.
//
// The monitor hands back tokens, never devices: it runs on the provider's
// nodes, and a device name there is a fact about the operator the provider
// should not hold. The names live here, in the fleet this machine enrolled,
// so a device enrolled from another machine — or before tokens were recorded
// — is said to be unnamed from here rather than guessed at.
func attributeTunnel(rows []shrike.TunnelStat, keepers []config.Keeper, operatorToken string, now time.Time) []tunnelRow {
	out := make([]tunnelRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, tunnelRow{
			Who:  tunnelPeerName(r.Role, r.Peer, keepers, operatorToken, now),
			Role: r.Role, Peer: r.Peer, Route: r.Route,
			Relayed: r.Relayed, Refused: r.Refused, Reasons: r.Reasons, Failed: r.Failed,
			BytesUp: r.BytesUp, BytesDown: r.BytesDown, LastSeen: r.LastSeen,
		})
	}
	return out
}

// unnamedKeeper is a keeper leaf this machine has no record of issuing.
const unnamedKeeper = "keeper (leaf not enrolled from this machine)"

func tunnelPeerName(role, token string, keepers []config.Keeper, operatorToken string, now time.Time) string {
	switch role {
	case "":
		return "(peer not reported — FatLine predates attribution)"
	case event.PeerOperator:
		// The role is FatLine's verified decision; the token only says
		// whether it was THIS machine's leaf. Unknown here is not a
		// different operator — it is a leaf this machine cannot read.
		if operatorToken != "" && token != operatorToken {
			return "operator (another leaf)"
		}
		return "operator"
	case event.PeerKeeper:
		for _, k := range keepers {
			i := slices.Index(k.LeafTokens, token)
			if token == "" || i < 0 {
				continue
			}
			name := "keeper " + k.Device
			switch {
			case k.Revoked:
				// Revoked here and still valid there: a revocation is
				// bounded in the cluster by the leaf's own NotAfter.
				name += " (revoked)"
			case i < len(k.LeafTokens)-1:
				// Re-enrolled since, and the older leaf is still in use.
				name += " (an earlier leaf)"
			case !k.Expires.IsZero() && now.After(k.Expires):
				name += " (expired)"
			}
			return name
		}
		return unnamedKeeper
	default:
		return role
	}
}
