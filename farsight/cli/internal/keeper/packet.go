// Package keeper implements FarCast's keeper devices: operator-owned hardware
// that re-seeds a restart-sealed keyholder without waking anyone.
//
// The design is [ADR 0008]'s keeper fleet, and every constraint it records is
// load-bearing here rather than aspirational:
//
//   - A keeper holds a derived scope BUNDLE and its own device leaf. It never
//     holds the master keyring, and it never holds the instance CA key — so a
//     stolen keeper can re-seed and cannot mint another keeper.
//   - A keeper's private key is made on the keeper, and nothing here sends it
//     anywhere (ADR 0020 decision 3). The device sends a request carrying
//     the public key; the packet that comes back carries a certificate for
//     that key and the bundle, and never a key — install refuses a
//     certificate for any other key as a security event.
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
// [ADR 0020]: ../../../../docs/adr/0020-instance-pki-ecdsa-p256.md
package keeper

import (
	"fmt"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/datasphere"
)

// packetVersion is the wire schema of an enrolment packet. Version 1 carried
// the device's private key, minted on the operator's machine; ADR 0020 retired
// it, and version 2 carries a certificate for a key the device made.
const packetVersion = 2

// recordVersion is the schema of keeper.yaml, the installed keeper's record.
// It is its own number: the record did not change shape when the packet did.
const recordVersion = 1

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
// certificate for the key the device made, what it needs to reach and verify
// the instance, and the scope bundle it will push. It carries no private key:
// the device's key never left the device. Assembling it is the operator's
// act, on the operator's machine — a packet never comes through the instance,
// which must not become a distributor of the material it is fed.
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
	// LeafKeyPEM is read only to be refused: a version 2 packet never
	// carries a private key, and 'keeper enroll' never sets it. A packet that
	// holds one was not made by this build's enroll (ADR 0020).
	LeafKeyPEM []byte `yaml:"leaf_key_pem,omitempty"`

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

// Validate checks a packet is internally complete, and carries no key.
func (p *Packet) Validate() error {
	switch {
	case p == nil:
		return fmt.Errorf("keeper: no packet")
	case p.Version == 1:
		return fmt.Errorf("keeper: this is a version 1 packet, which carries the device's private key; ADR 0020 retired it " +
			"(docs/adr/0020-instance-pki-ecdsa-p256.md). Enrol the device again by request: 'farcast keeper request <instance>' " +
			"on the device, then 'farcast keeper enroll … --request' on the operator's machine")
	case p.Version != packetVersion:
		return fmt.Errorf("keeper: packet version %d is not supported by this build", p.Version)
	case len(p.LeafKeyPEM) > 0:
		return fmt.Errorf("keeper: this packet carries a private key, which a version 2 packet never does (ADR 0020): " +
			"'farcast keeper enroll' did not write it. Do not install it; tell the operator")
	case strings.TrimSpace(p.Instance) == "":
		return fmt.Errorf("keeper: packet names no instance")
	case ValidateInstance(p.Instance) != nil:
		// Install joins this name into a directory path, reads keys from it,
		// and prints it in a security event.
		return ValidateInstance(p.Instance)
	case ValidateDevice(p.Device) != nil:
		return ValidateDevice(p.Device)
	case strings.TrimSpace(p.Carrier) == "":
		return fmt.Errorf("keeper: packet carries no carrier address, so the device cannot reach the instance")
	case strings.TrimSpace(p.ServerName) == "":
		return fmt.Errorf("keeper: packet carries no server name, so the device cannot verify what answers")
	case len(p.CACertPEM) == 0:
		return fmt.Errorf("keeper: packet carries no CA certificate, so the device cannot verify the instance at all")
	case len(p.LeafCertPEM) == 0:
		return fmt.Errorf("keeper: packet carries no device certificate")
	case len(p.Bundle) == 0:
		return fmt.Errorf("keeper: packet carries no bundle, so the device has nothing to re-seed with")
	case p.Budget <= 0:
		return fmt.Errorf("keeper: packet carries no reseed budget; an unbounded keeper is a solicitation endpoint with no tripwire")
	case p.Window <= 0:
		return fmt.Errorf("keeper: packet carries no budget window")
	}
	return nil
}

// Zero overwrites the packet's key material in place: the bundle, and a
// private key a packet should never have carried.
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
	if err := decodePacket(plaintext, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// decodePacket decodes plaintext into p and validates it. On a refusal it
// zeroes what it decoded first: the packets refused for carrying a private
// key are exactly the ones whose decoded key and bundle Zero exists for.
func decodePacket(plaintext []byte, p *Packet) error {
	if err := yaml.Unmarshal(plaintext, p); err != nil {
		p.Zero()
		// The parser quotes source around an error, and this source is key
		// material. Only the shape is reported.
		return fmt.Errorf("keeper: the packet did not decode")
	}
	if err := p.Validate(); err != nil {
		p.Zero()
		return err
	}
	return nil
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
