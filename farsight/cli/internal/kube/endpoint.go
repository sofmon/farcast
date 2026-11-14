package kube

import (
	"crypto/x509"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Mode is where a cluster lives: Google's DNS endpoint, or a loopback test server.
type Mode int

const (
	ModeGoogle   Mode = 1
	ModeLoopback Mode = 2
)

// String names the mode as the refusal messages do: "Google" or "loopback".
func (m Mode) String() string {
	switch m {
	case ModeGoogle:
		return "Google"
	case ModeLoopback:
		return "loopback"
	}
	return "unknown"
}

// Endpoint is a classified API server address (§3.1).
type Endpoint struct {
	Mode Mode
	Host string         // lower-case DNS name (Google) or canonical IP literal (loopback)
	Port string         // "443" (Google, always) or the recorded port (loopback)
	CA   *x509.CertPool // nil in Google mode: the system roots
}

// googleHost is a DNS name under gke.goog with at least one label before it.
var googleHost = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+gke\.goog$`)

// The loopback ranges: 127.0.0.0/8 and ::1. Nothing else, and in particular no
// IPv4-mapped form of either.
var loopbackV4 = netip.MustParsePrefix("127.0.0.0/8")

// clusterCAFile is how the refusals name the instance's cluster CA file.
const clusterCAFile = "cluster-ca.crt"

// The refusal messages of §3.1, each wrapping ErrEndpointRefused.
const (
	msgShape    = "the instance records the cluster endpoint %q, which is neither a name under gke.goog nor a loopback IP literal with its port; nothing was sent"
	msgMapped   = "the instance records the endpoint %q, an IPv4-mapped IPv6 address, which is never a loopback endpoint; nothing was sent"
	msgRange    = "the instance records the endpoint %q, an IP literal outside 127.0.0.0/8 and ::1; nothing was sent"
	msgPort     = "the instance records the endpoint %q with port %q; a Google endpoint is port 443 only, and a loopback endpoint names a port from 1 to 65535; nothing was sent"
	msgRegion   = "the instance records the Google endpoint %q, and none of its labels is the instance's region %q; nothing was sent"
	msgGoogleCA = "the instance records the Google endpoint %q, and %s exists: a Google endpoint is trusted on the system roots alone, so a cluster CA beside it is refused; nothing was sent"
	msgNoCA     = "the instance records the loopback endpoint %q with no cluster-ca.crt; a loopback endpoint is trusted only on its own CA; nothing was sent"
	msgNoCert   = "%s holds no certificate"
)

// ParseEndpoint classifies an instance's recorded endpoint (metadata.yaml "endpoint")
// against its recorded region (metadata.yaml "region", used in Google mode only) and
// the PEM of its cluster-ca.crt (nil when the file is absent). It refuses everything
// §3.1 does not accept, with an error wrapping ErrEndpointRefused.
//
// It makes no DNS lookup and dials nothing: the name localhost is refused
// because it is not under gke.goog, not because of what it resolves to.
func ParseEndpoint(recorded, region string, caPEM []byte) (Endpoint, error) {
	shape := func() (Endpoint, error) { return Endpoint{}, refuse(ErrEndpointRefused, msgShape, recorded) }

	// 1. Shape.
	if recorded == "" || strings.Contains(recorded, "://") || strings.ContainsAny(recorded, "/?#@") ||
		strings.ContainsFunc(recorded, unicode.IsSpace) {
		return shape()
	}

	// 2. Host and port.
	var host, port string
	var hasPort, bracketed bool
	switch {
	case strings.HasPrefix(recorded, "["):
		h, p, err := net.SplitHostPort(recorded)
		if err != nil || recorded != "["+h+"]:"+p {
			return shape()
		}
		host, port, hasPort, bracketed = h, p, true, true
	case strings.Count(recorded, ":") == 1:
		h, p, err := net.SplitHostPort(recorded)
		if err != nil {
			return shape()
		}
		host, port, hasPort = h, p, true
	case strings.Count(recorded, ":") > 1:
		// A bare IPv6 literal (::1, ::ffff:127.0.0.1) names no port.
		return shape()
	default:
		host = recorded
	}
	if host == "" || strings.HasSuffix(host, ".") {
		return shape()
	}

	// 3. Loopback.
	if addr, err := netip.ParseAddr(host); err == nil {
		if bracketed && !addr.Is6() {
			// Brackets carry an IPv6 literal only.
			return shape()
		}
		if addr.Is4In6() {
			return Endpoint{}, refuse(ErrEndpointRefused, msgMapped, recorded)
		}
		if !loopbackV4.Contains(addr) && addr != netip.IPv6Loopback() {
			return Endpoint{}, refuse(ErrEndpointRefused, msgRange, recorded)
		}
		if !hasPort || !validPort(port) {
			return Endpoint{}, refuse(ErrEndpointRefused, msgPort, recorded, port)
		}
		if caPEM == nil {
			return Endpoint{}, refuse(ErrEndpointRefused, msgNoCA, recorded)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return Endpoint{}, refuse(ErrEndpointRefused, msgNoCert, clusterCAFile)
		}
		return Endpoint{Mode: ModeLoopback, Host: addr.String(), Port: port, CA: pool}, nil
	}
	if bracketed {
		return shape()
	}

	// 4. Google.
	host = strings.ToLower(host)
	if !googleHost.MatchString(host) {
		return shape()
	}
	labels := strings.Split(host, ".")
	wantRegion := strings.ToLower(region)
	inRegion := false
	for _, l := range labels[1:] {
		if l == wantRegion {
			inRegion = true
			break
		}
	}
	if !inRegion {
		return Endpoint{}, refuse(ErrEndpointRefused, msgRegion, recorded, region)
	}
	if hasPort && port != "443" {
		return Endpoint{}, refuse(ErrEndpointRefused, msgPort, recorded, port)
	}
	if caPEM != nil {
		return Endpoint{}, refuse(ErrEndpointRefused, msgGoogleCA, recorded, clusterCAFile)
	}
	return Endpoint{Mode: ModeGoogle, Host: host, Port: "443"}, nil
}

// validPort is a decimal port from 1 to 65535, written canonically: no sign,
// no leading zero.
func validPort(p string) bool {
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == p
}

// BaseURL is the API server's origin: "https://h" (Google), "https://127.0.0.1:p",
// "https://[::1]:p". It is "" for an Endpoint ParseEndpoint did not make.
func (e Endpoint) BaseURL() string {
	switch e.Mode {
	case ModeGoogle:
		return "https://" + e.Host
	case ModeLoopback:
		return "https://" + net.JoinHostPort(e.Host, e.Port)
	}
	return ""
}

// TokenURL is where a token for this endpoint is minted: GoogleTokenURL, or
// BaseURL()+"/token" in loopback mode. It is never read from a key file.
func (e Endpoint) TokenURL() string {
	switch e.Mode {
	case ModeGoogle:
		return GoogleTokenURL
	case ModeLoopback:
		return e.BaseURL() + "/token"
	}
	return ""
}
