package keyholder

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func issue(t *testing.T, c *Challenger) Challenge {
	t.Helper()
	ch, err := c.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return ch
}

func TestEnvelopeRoundTrip(t *testing.T) {
	c, err := NewChallenger()
	if err != nil {
		t.Fatalf("NewChallenger: %v", err)
	}
	payload := marshalBundle(t, "prod", 3)

	sealed, err := SealBundle(payload, "prod", issue(t, c))
	if err != nil {
		t.Fatalf("SealBundle: %v", err)
	}
	if bytes.Contains(sealed, payload) {
		t.Fatal("the envelope carries its payload in the clear")
	}
	got, err := c.Open(sealed, "prod")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("round trip changed the payload")
	}
}

// A challenge is single-use. Without this, a captured envelope could be pushed
// again into the same live process.
func TestChallengeIsSingleUse(t *testing.T) {
	c, _ := NewChallenger()
	ch := issue(t, c)
	sealed, err := SealBundle(marshalBundle(t, "prod", 1), "prod", ch)
	if err != nil {
		t.Fatalf("SealBundle: %v", err)
	}
	if _, err := c.Open(sealed, "prod"); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := c.Open(sealed, "prod"); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Fatal("an envelope was accepted twice")
	}
}

// A FAILED open must also consume the challenge. A challenge that survived a
// failure would let a caller retry against it, which is the oracle single use
// exists to deny.
func TestFailedOpenConsumesTheChallenge(t *testing.T) {
	c, _ := NewChallenger()
	ch := issue(t, c)
	sealed, err := SealBundle(marshalBundle(t, "prod", 1), "prod", ch)
	if err != nil {
		t.Fatalf("SealBundle: %v", err)
	}
	// Fail once by naming the wrong instance.
	if _, err := c.Open(sealed, "staging"); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Fatal("the wrong instance was accepted")
	}
	// The correct instance must now fail too: the challenge is spent.
	if _, err := c.Open(sealed, "prod"); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Fatal("a challenge survived a failed open; a caller could retry against it")
	}
}

// The recipient key is per process and never written anywhere, so an envelope
// captured on the wire cannot be opened by a later process — including one the
// cloud starts after forcing a restart.
func TestEnvelopeCannotBeOpenedByAnotherProcess(t *testing.T) {
	first, _ := NewChallenger()
	sealed, err := SealBundle(marshalBundle(t, "prod", 1), "prod", issue(t, first))
	if err != nil {
		t.Fatalf("SealBundle: %v", err)
	}
	restarted, _ := NewChallenger()
	if _, err := restarted.Open(sealed, "prod"); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Fatal("a restarted process opened an envelope sealed to its predecessor")
	}
	if bytes.Equal(first.PublicKey(), restarted.PublicKey()) {
		t.Fatal("two processes minted the same recipient key")
	}
}

func TestEnvelopeIsBoundToItsInstance(t *testing.T) {
	// The two names are the SAME LENGTH on purpose. The AAD carries a length
	// prefix, so differently-sized names would be rejected by the length
	// alone and this test would pass even if the name itself were dropped
	// from the AAD entirely.
	for _, other := range []string{"test", "acme"} {
		c, _ := NewChallenger()
		sealed, err := SealBundle(marshalBundle(t, "prod", 1), "prod", issue(t, c))
		if err != nil {
			t.Fatalf("SealBundle: %v", err)
		}
		if len(other) != len("prod") {
			t.Fatalf("guard: %q must be the same length as %q", other, "prod")
		}
		if _, err := c.Open(sealed, other); !errors.Is(err, ErrEnvelopeInvalid) {
			t.Fatalf("an envelope for %q opened against %q", "prod", other)
		}
	}
}

// (4) The challenge enters BOTH the AEAD's associated data and the key
// derivation. The AAD binding alone would make the derivation binding
// untestable through Open, so it is pinned directly here: two challenges must
// yield keys that cannot open each other's output.
func TestChallengeBindsTheDerivedKey(t *testing.T) {
	recipient := make([]byte, pubKeyLen)
	sender := make([]byte, pubKeyLen)
	shared := bytes.Repeat([]byte{7}, 32)
	challengeA := bytes.Repeat([]byte{1}, challengeLen)
	challengeB := bytes.Repeat([]byte{2}, challengeLen)

	a, err := envelopeCipher(shared, recipient, sender, challengeA)
	if err != nil {
		t.Fatalf("envelopeCipher(A): %v", err)
	}
	b, err := envelopeCipher(shared, recipient, sender, challengeB)
	if err != nil {
		t.Fatalf("envelopeCipher(B): %v", err)
	}
	nonce := make([]byte, nonceLen)
	sealedA := a.Seal(nil, nonce, []byte("key material"), nil)
	if _, err := b.Open(nil, nonce, sealedA, nil); err == nil {
		t.Fatal("a key derived for one challenge opened another challenge's output")
	}

	// And the peers' public halves bind it too.
	other, err := envelopeCipher(shared, recipient, bytes.Repeat([]byte{9}, pubKeyLen), challengeA)
	if err != nil {
		t.Fatalf("envelopeCipher(other sender): %v", err)
	}
	if _, err := other.Open(nil, nonce, sealedA, nil); err == nil {
		t.Fatal("a key derived against a different sender opened the output")
	}
}

// Every byte is authenticated. The sweep covers the whole envelope rather than
// named regions, so no byte can escape it as the format evolves.
func TestEveryByteIsAuthenticated(t *testing.T) {
	payload := marshalBundle(t, "prod", 1)
	for i := range sealOnce(t, payload) {
		c, _ := NewChallenger()
		sealed, err := SealBundle(payload, "prod", issue(t, c))
		if err != nil {
			t.Fatalf("SealBundle: %v", err)
		}
		sealed[i] ^= 0x01
		if _, err := c.Open(sealed, "prod"); !errors.Is(err, ErrEnvelopeInvalid) {
			t.Fatalf("a bit flip at offset %d of %d was accepted", i, len(sealed))
		}
	}
}

func TestTruncatedEnvelopesAreRefused(t *testing.T) {
	c, _ := NewChallenger()
	sealed, err := SealBundle(marshalBundle(t, "prod", 1), "prod", issue(t, c))
	if err != nil {
		t.Fatalf("SealBundle: %v", err)
	}
	for _, n := range []int{0, 1, 4, 5, offSenderPub, offNonce, offCiphertext, len(sealed) - 1} {
		if _, err := c.Open(sealed[:n], "prod"); !errors.Is(err, ErrEnvelopeInvalid) {
			t.Errorf("a %d-byte envelope was accepted", n)
		}
	}
}

func TestExpiredChallengeIsRefused(t *testing.T) {
	c, _ := NewChallenger()
	now := time.Now()
	c.now = func() time.Time { return now }
	ch := issue(t, c)
	sealed, err := SealBundle(marshalBundle(t, "prod", 1), "prod", ch)
	if err != nil {
		t.Fatalf("SealBundle: %v", err)
	}
	c.now = func() time.Time { return now.Add(challengeTTL + time.Second) }
	if _, err := c.Open(sealed, "prod"); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Fatal("an expired challenge was accepted")
	}
}

// Every refusal is the same error. A caller learns that the push was refused
// and nothing about which check refused it.
func TestAllRefusalsAreIndistinguishable(t *testing.T) {
	payload := marshalBundle(t, "prod", 1)
	build := func() (*Challenger, []byte) {
		c, _ := NewChallenger()
		sealed, err := SealBundle(payload, "prod", issue(t, c))
		if err != nil {
			t.Fatalf("SealBundle: %v", err)
		}
		return c, sealed
	}

	var messages []string
	// Wrong instance.
	c1, s1 := build()
	_, e1 := c1.Open(s1, "staging")
	// Unknown session.
	c2, s2 := build()
	s2[offSessionID] ^= 0xff
	_, e2 := c2.Open(s2, "prod")
	// Bad magic.
	c3, s3 := build()
	s3[0] ^= 0xff
	_, e3 := c3.Open(s3, "prod")
	// Unknown version.
	c4, s4 := build()
	s4[offVersion] = 0x7f
	_, e4 := c4.Open(s4, "prod")
	// Corrupt ciphertext.
	c5, s5 := build()
	s5[len(s5)-1] ^= 0xff
	_, e5 := c5.Open(s5, "prod")

	for _, err := range []error{e1, e2, e3, e4, e5} {
		if !errors.Is(err, ErrEnvelopeInvalid) {
			t.Fatalf("refusal was not ErrEnvelopeInvalid: %v", err)
		}
		messages = append(messages, err.Error())
	}
	for _, m := range messages[1:] {
		if m != messages[0] {
			t.Errorf("refusals differ: %q vs %q — the difference is an oracle", m, messages[0])
		}
	}
}

func TestOutstandingChallengesAreBounded(t *testing.T) {
	c, _ := NewChallenger()
	for i := range maxOutstanding {
		if _, err := c.Issue(); err != nil {
			t.Fatalf("Issue %d: %v", i, err)
		}
	}
	if _, err := c.Issue(); err == nil {
		t.Fatal("Issue is unbounded; a caller could exhaust memory")
	}
}

func TestSealRefusesMalformedChallenge(t *testing.T) {
	good := Challenge{SessionID: make([]byte, sessionIDLen), Nonce: make([]byte, challengeLen), PublicKey: make([]byte, pubKeyLen)}
	bad := []Challenge{
		{},
		{SessionID: make([]byte, 4), Nonce: good.Nonce, PublicKey: good.PublicKey},
		{SessionID: good.SessionID, Nonce: make([]byte, 8), PublicKey: good.PublicKey},
		{SessionID: good.SessionID, Nonce: good.Nonce, PublicKey: make([]byte, 8)},
	}
	for i, ch := range bad {
		if _, err := SealBundle([]byte("x"), "prod", ch); err == nil {
			t.Errorf("case %d: SealBundle accepted a malformed challenge", i)
		}
	}
}

func sealOnce(t *testing.T, payload []byte) []byte {
	t.Helper()
	c, _ := NewChallenger()
	sealed, err := SealBundle(payload, "prod", issue(t, c))
	if err != nil {
		t.Fatalf("SealBundle: %v", err)
	}
	return sealed
}
