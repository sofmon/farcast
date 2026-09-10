// Package keeper implements FarCast's keeper devices: operator-owned hardware
// that re-seeds a restart-sealed keyholder without waking anyone.
//
// The design is [ADR 0008]'s keeper fleet, and every constraint it records is
// load-bearing here rather than aspirational:
//
//   - A keeper holds a derived scope BUNDLE and its own device leaf. It never
//     holds the master keyring, and it never holds the instance CA key — so a
//     stolen keeper can re-seed and cannot mint another keeper.
//   - A keeper is OUTBOUND-ONLY. It dials FatLine; nothing listens on it, so
//     every flow of key material starts on the operator's own hardware.
//   - A keeper never clears a deliberate seal. "Sealed because restarted" and
//     "sealed because the operator said so" are different states and only the
//     first is a keeper's to remedy.
//   - Every push lands in a local append-only ledger the cloud can neither
//     reach nor erase, and beyond a budget the keeper refuses rather than
//     re-seeding. The budget is a tripwire, not a barrier: a patient adversary
//     stays under it, which is why the ledger has to actually be read.
//
// [ADR 0008]: ../../../../docs/adr/0008-in-cluster-key-delivery.md
package keeper

import (
	"fmt"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/datasphere"
)

// packetVersion is the wire schema of an enrolment packet.
const packetVersion = 1

// DefaultBudget and DefaultWindow bound how often a keeper may re-seed before
// it refuses and asks for a human.
//
// The number comes from what the platform actually does: Autopilot restarts a
// workload once or twice a month for upgrades, repair and rescheduling, and an
// instance runs two keyholder replicas, so a busy month is a handful of pushes.
// Set it far above that and the tripwire never trips; set it at the expected
// count and honest maintenance pages somebody at 03:00.
const (
	DefaultBudget = 8
	DefaultWindow = 30 * 24 * time.Hour
)

// Packet is what an operator hands to a device to enrol it.
//
// It carries three things that must travel together and nothing else: the
// device's own leaf, what it needs to reach and verify the instance, and the
// scope bundle it will push. Assembling it is the operator's act, on the
// operator's machine — a packet never comes through the instance, which must
// not become a distributor of the material it is fed.
type Packet struct {
	Version  int    `yaml:"version"`
	Instance string `yaml:"instance"`
	Device   string `yaml:"device"`

	// Carrier is FatLine's public address, and ServerName is the identity its
	// certificate must present. They are separate because they are different
	// things: the address is whatever the carrier happens to listen on, and
	// the name is verified against the instance's own CA and never resolves in
	// public DNS (ADR 0005).
	Carrier    string `yaml:"carrier"`
	ServerName string `yaml:"server_name"`

	CACertPEM   []byte `yaml:"ca_cert_pem"`
	LeafCertPEM []byte `yaml:"leaf_cert_pem"`
	LeafKeyPEM  []byte `yaml:"leaf_key_pem"`

	// Bundle is a marshalled datasphere.Bundle: scope keys and their ids. It
	// is exactly what an unsealed keyholder already holds in RAM, and no more
	// — which is the property that lets a keeper push one without widening
	// what a compromised cluster can yield.
	Bundle     []byte `yaml:"bundle"`
	Generation uint64 `yaml:"generation"`

	Budget   int           `yaml:"budget"`
	Window   time.Duration `yaml:"window"`
	IssuedAt time.Time     `yaml:"issued_at"`
}

// Validate checks a packet is internally complete.
func (p *Packet) Validate() error {
	switch {
	case p == nil:
		return fmt.Errorf("keeper: no packet")
	case p.Version != packetVersion:
		return fmt.Errorf("keeper: packet version %d is not supported by this build", p.Version)
	case strings.TrimSpace(p.Instance) == "":
		return fmt.Errorf("keeper: packet names no instance")
	case ValidateDevice(p.Device) != nil:
		return ValidateDevice(p.Device)
	case strings.TrimSpace(p.Carrier) == "":
		return fmt.Errorf("keeper: packet carries no carrier address, so the device cannot reach the instance")
	case strings.TrimSpace(p.ServerName) == "":
		return fmt.Errorf("keeper: packet carries no server name, so the device cannot verify what answers")
	case len(p.CACertPEM) == 0:
		return fmt.Errorf("keeper: packet carries no CA certificate, so the device cannot verify the instance at all")
	case len(p.LeafCertPEM) == 0 || len(p.LeafKeyPEM) == 0:
		return fmt.Errorf("keeper: packet carries no device identity")
	case len(p.Bundle) == 0:
		return fmt.Errorf("keeper: packet carries no bundle, so the device has nothing to re-seed with")
	case p.Budget <= 0:
		return fmt.Errorf("keeper: packet carries no reseed budget; an unbounded keeper is a solicitation endpoint with no tripwire")
	case p.Window <= 0:
		return fmt.Errorf("keeper: packet carries no budget window")
	}
	return nil
}

// Zero overwrites the packet's key material in place.
//
// Hygiene rather than a guarantee, exactly as datasphere.Bundle.Zero says of
// itself: the garbage collector may already have copied these bytes. It
// shortens the window in which a packet sits in a live heap, which is worth
// doing on a path that exists to move key material between machines.
func (p *Packet) Zero() {
	if p == nil {
		return
	}
	clear(p.Bundle)
	clear(p.LeafKeyPEM)
	p.Bundle, p.LeafKeyPEM = nil, nil
}

// Seal renders a packet as passphrase-armored bytes, ready to carry to a
// device on whatever medium the operator trusts.
func Seal(p *Packet, passphrase string) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	plaintext, err := yaml.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("keeper: encode the packet: %w", err)
	}
	defer clear(plaintext)
	return datasphere.Armor(datasphere.ArmorKeeperPacket, plaintext, passphrase)
}

// Open unseals a packet.
func Open(data []byte, passphrase string) (*Packet, error) {
	plaintext, err := datasphere.Unarmor(datasphere.ArmorKeeperPacket, data, passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var p Packet
	if err := yaml.Unmarshal(plaintext, &p); err != nil {
		// The parser quotes source around an error, and this source is key
		// material. Only the shape is reported.
		return nil, fmt.Errorf("keeper: the packet did not decode")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// MaxDeviceLen bounds a device name. It becomes part of a certificate URI and
// a directory name, and an operator types it into both.
const MaxDeviceLen = 63

// ValidateDevice holds a device name to a DNS label.
//
// The name is not decoration: it is what `keeper revoke` names, what a ledger
// entry is attributed to, and what distinguishes one device's leaf from
// another's. A fleet whose devices are not separately nameable cannot have one
// member revoked.
func ValidateDevice(device string) error {
	if device == "" {
		return fmt.Errorf("keeper: a device name is required, so that one device can be revoked without revoking the fleet")
	}
	if len(device) > MaxDeviceLen {
		return fmt.Errorf("keeper: a device name must be at most %d bytes", MaxDeviceLen)
	}
	if device[0] < 'a' || device[0] > 'z' {
		return fmt.Errorf("keeper: a device name must start with a lowercase letter")
	}
	for i := 0; i < len(device); i++ {
		c := device[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return fmt.Errorf("keeper: a device name may use only lowercase letters, digits and dashes")
		}
	}
	if device[len(device)-1] == '-' {
		return fmt.Errorf("keeper: a device name must not end with a dash")
	}
	return nil
}
