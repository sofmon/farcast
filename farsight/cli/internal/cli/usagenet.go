package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
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
// loopback of the very Pod that relayed it, and carries decision counts. The
// operator is already authenticated by the tunnel itself.
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
