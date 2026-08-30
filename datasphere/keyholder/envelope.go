package keyholder

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// The unseal envelope: a second layer under the mTLS session that carries a
// bundle from the operator's machine into one specific keyholder process.
//
// What it buys, stated precisely:
//
//   - A captured envelope cannot be opened by a LATER process. The recipient
//     key is minted per process from crypto/rand and never written anywhere,
//     so a restarted keyholder — including one the cloud starts — holds a
//     different private half.
//   - It cannot be replayed into the SAME process: the challenge is consumed
//     on first use, whether that use succeeded or failed.
//   - It cannot be redirected at another instance: the instance name is
//     authenticated as associated data.
//   - It cannot be altered: the bundle, and therefore its generation, is
//     inside the AEAD.
//
// What it does NOT buy, because overpromising here would be worse than not
// promising: a cloud that reads the keyholder's TLS Secret can impersonate the
// keyholder at push time, mint its own ephemeral key, and receive the bundle —
// the challenge travels inside the very session being impersonated. That is
// ADR 0008's solicitation oracle arriving in 3.2, and the answer to it is
// detection and the reseed budget, not this envelope.
const (
	envelopeMagic   = "FCUS"
	envelopeVersion = 1

	sessionIDLen = 8
	challengeLen = 32
	pubKeyLen    = 32
	nonceLen     = 12

	offVersion    = 4
	offSessionID  = 5
	offSenderPub  = offSessionID + sessionIDLen
	offNonce      = offSenderPub + pubKeyLen
	offCiphertext = offNonce + nonceLen

	// envelopeInfo is the HKDF info prefix. It follows the module's pinned
	// single-shot shape: SHA-256, nil salt, 32-byte output, variation only
	// through info.
	envelopeInfo = "farcast/datasphere/v1/unseal"

	// challengeTTL bounds how long an issued challenge stays openable.
	challengeTTL = 2 * time.Minute
	// maxOutstanding bounds memory against a caller that requests challenges
	// and never uses them. The control surface is mTLS-gated, so this is a
	// bound on a mistake rather than on an anonymous attacker.
	maxOutstanding = 64
)

// ErrEnvelopeInvalid reports an envelope that could not be opened.
//
// It is deliberately one error for every failure — bad magic, unknown version,
// unknown or expired session, wrong instance, failed authentication. A caller
// learns that the push was refused and nothing about which check refused it.
var ErrEnvelopeInvalid = errors.New("keyholder: unseal envelope refused")

// Challenge is what a keyholder offers before it will accept a bundle.
type Challenge struct {
	SessionID []byte `json:"session_id"`
	Nonce     []byte `json:"challenge"`
	PublicKey []byte `json:"public_key"`
}

// Challenger issues single-use challenges and opens the envelopes that answer
// them. Its private key exists only in this process's memory.
type Challenger struct {
	mu          sync.Mutex
	priv        *ecdh.PrivateKey
	outstanding map[[sessionIDLen]byte]time.Time
	nonces      map[[sessionIDLen]byte][challengeLen]byte
	now         func() time.Time
}

// NewChallenger mints the per-process recipient key.
func NewChallenger() (*Challenger, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keyholder: mint recipient key: %w", err)
	}
	return &Challenger{
		priv:        priv,
		outstanding: map[[sessionIDLen]byte]time.Time{},
		nonces:      map[[sessionIDLen]byte][challengeLen]byte{},
		now:         func() time.Time { return time.Now() },
	}, nil
}

// PublicKey is the recipient half a pusher seals to.
func (c *Challenger) PublicKey() []byte { return c.priv.PublicKey().Bytes() }

// Issue returns a fresh single-use challenge.
func (c *Challenger) Issue() (Challenge, error) {
	var session [sessionIDLen]byte
	var nonce [challengeLen]byte
	if _, err := io.ReadFull(rand.Reader, session[:]); err != nil {
		return Challenge{}, fmt.Errorf("keyholder: mint session id: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return Challenge{}, fmt.Errorf("keyholder: mint challenge: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	if len(c.outstanding) >= maxOutstanding {
		return Challenge{}, errors.New("keyholder: too many outstanding challenges")
	}
	c.outstanding[session] = c.now().Add(challengeTTL)
	c.nonces[session] = nonce

	return Challenge{
		SessionID: session[:],
		Nonce:     nonce[:],
		PublicKey: c.PublicKey(),
	}, nil
}

// Open authenticates and decrypts an envelope, consuming its challenge.
//
// The challenge is consumed whether or not the open succeeds. A challenge that
// survived a failure would let a caller retry against it, which is exactly the
// oracle single use exists to deny.
func (c *Challenger) Open(envelope []byte, instance string) ([]byte, error) {
	if len(envelope) < offCiphertext+16 {
		return nil, ErrEnvelopeInvalid
	}
	if string(envelope[:4]) != envelopeMagic || envelope[offVersion] != envelopeVersion {
		return nil, ErrEnvelopeInvalid
	}

	var session [sessionIDLen]byte
	copy(session[:], envelope[offSessionID:offSessionID+sessionIDLen])

	c.mu.Lock()
	c.expireLocked()
	deadline, known := c.outstanding[session]
	nonce := c.nonces[session]
	// Consume first, so every path below is a single attempt.
	delete(c.outstanding, session)
	delete(c.nonces, session)
	now := c.now()
	c.mu.Unlock()

	if !known || now.After(deadline) {
		return nil, ErrEnvelopeInvalid
	}

	senderPub, err := ecdh.X25519().NewPublicKey(envelope[offSenderPub : offSenderPub+pubKeyLen])
	if err != nil {
		return nil, ErrEnvelopeInvalid
	}
	shared, err := c.priv.ECDH(senderPub)
	if err != nil {
		return nil, ErrEnvelopeInvalid
	}
	defer clear(shared)

	gcm, err := envelopeCipher(shared, c.PublicKey(), senderPub.Bytes(), nonce[:])
	if err != nil {
		return nil, ErrEnvelopeInvalid
	}
	plaintext, err := gcm.Open(nil,
		envelope[offNonce:offNonce+nonceLen],
		envelope[offCiphertext:],
		envelopeAAD(instance, session[:], nonce[:]))
	if err != nil {
		return nil, ErrEnvelopeInvalid
	}
	return plaintext, nil
}

// SealBundle wraps a marshalled bundle for one keyholder process.
//
// It runs on the operator's machine (and, from 5.4, a keeper device), which is
// why it lives beside Open: one file holds both halves of the format, so a
// change cannot be made to one side alone.
func SealBundle(plaintext []byte, instance string, ch Challenge) ([]byte, error) {
	if len(ch.SessionID) != sessionIDLen || len(ch.Nonce) != challengeLen || len(ch.PublicKey) != pubKeyLen {
		return nil, fmt.Errorf("%w: malformed challenge", ErrEnvelopeInvalid)
	}
	recipient, err := ecdh.X25519().NewPublicKey(ch.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed recipient key", ErrEnvelopeInvalid)
	}
	sender, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keyholder: mint sender key: %w", err)
	}
	shared, err := sender.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("%w: key agreement failed", ErrEnvelopeInvalid)
	}
	defer clear(shared)

	gcm, err := envelopeCipher(shared, ch.PublicKey, sender.PublicKey().Bytes(), ch.Nonce)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("keyholder: mint envelope nonce: %w", err)
	}

	out := make([]byte, 0, offCiphertext+len(plaintext)+16)
	out = append(out, envelopeMagic...)
	out = append(out, envelopeVersion)
	out = append(out, ch.SessionID...)
	out = append(out, sender.PublicKey().Bytes()...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, envelopeAAD(instance, ch.SessionID, ch.Nonce)), nil
}

// envelopeCipher derives the one-use key. Both public halves and the challenge
// enter the info, so a shared secret computed against a different peer, or
// answering a different challenge, yields a different key.
func envelopeCipher(shared, recipientPub, senderPub, challenge []byte) (cipher.AEAD, error) {
	info := envelopeInfo + string(recipientPub) + string(senderPub) + string(challenge)
	key, err := hkdf.Key(sha256.New, shared, nil, info, 32)
	if err != nil {
		return nil, fmt.Errorf("keyholder: derive envelope key: %w", err)
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keyholder: envelope cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// envelopeAAD binds the envelope to an instance and a challenge.
func envelopeAAD(instance string, session, challenge []byte) []byte {
	aad := make([]byte, 0, 4+1+8+len(instance)+len(session)+len(challenge))
	aad = append(aad, envelopeMagic...)
	aad = append(aad, envelopeVersion)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(instance)))
	aad = append(aad, n[:]...) // length-prefixed, so no instance name can be confused with another
	aad = append(aad, instance...)
	aad = append(aad, session...)
	aad = append(aad, challenge...)
	return aad
}

// expireLocked drops challenges past their deadline. The caller holds the lock.
func (c *Challenger) expireLocked() {
	now := c.now()
	for id, deadline := range c.outstanding {
		if now.After(deadline) {
			delete(c.outstanding, id)
			delete(c.nonces, id)
		}
	}
}
