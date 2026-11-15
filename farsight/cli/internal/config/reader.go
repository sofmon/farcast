package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Reader records an instance's read-only identity (ADR 0023 M2.3): the
// per-instance service account the cluster reads are to run as (ADR 0023
// M2.4), so a read never mints a token for the installer, which can write.
//
// Nothing secret lives here. The key is reader.key, a 0600 file beside this
// record; what is recorded is which account it signs for, which of that
// account's keys Google holds for it, and whether 'farcast reader grant' has
// verified the account read-only.
type Reader struct {
	// Email is the service account's email. Every use checks it against the
	// one farcast derives from the instance's name and project, so a
	// hand-edited email never makes a "reader" read as another account.
	Email string `yaml:"email"`
	// KeyID is the id Google printed when the human uploaded the key's
	// certificate in Cloud Shell; "" until 'farcast reader record'.
	KeyID string `yaml:"key_id,omitempty"`
	// GrantedAt is when 'farcast reader grant' applied the reader's RBAC and
	// then verified, as the reader, that it can read and cannot write. Zero
	// means not verified, and reads refuse.
	GrantedAt time.Time `yaml:"granted_at,omitempty"`
	// Scope is what the grant covered, set with GrantedAt: "metered", every
	// namespace the kernel meters, now and later (ADR 0023 M2, P3).
	Scope string `yaml:"scope,omitempty"`
}

// The reader's files, in the instance directory. The .next pair is a rotated
// key that is not yet in use: it becomes reader.key and reader.crt only when
// 'farcast reader record' is told the id Google gave it.
const (
	readerKeyFile      = "reader.key"
	readerCertFile     = "reader.crt"
	nextReaderKeyFile  = "reader.key.next"
	nextReaderCertFile = "reader.crt.next"
	// clusterCAFile is the CA a loopback cluster endpoint is trusted on. A
	// Google endpoint has none: it is trusted on the system roots alone.
	clusterCAFile = "cluster-ca.crt"
)

func (d Dir) instanceFile(name, file string) string {
	return filepath.Join(d.instanceDir(name), file)
}

// SaveReaderKey writes the reader's key and its certificate, reader.key and
// reader.crt, each 0600 and each written whole or not at all. The key is
// written first.
func (d Dir) SaveReaderKey(name string, keyPEM, certPEM []byte) error {
	return d.saveKeyPair(name, readerKeyFile, readerCertFile, keyPEM, certPEM)
}

// SaveNextReaderKey writes a rotated key and its certificate as
// reader.key.next and reader.crt.next ('farcast reader init --rotate'). The
// key in use is left alone, so every read keeps working with it until
// PromoteNextReaderKey.
func (d Dir) SaveNextReaderKey(name string, keyPEM, certPEM []byte) error {
	return d.saveKeyPair(name, nextReaderKeyFile, nextReaderCertFile, keyPEM, certPEM)
}

func (d Dir) saveKeyPair(name, keyFile, certFile string, keyPEM, certPEM []byte) error {
	if len(keyPEM) == 0 || len(certPEM) == 0 {
		return fmt.Errorf("write %s and %s: a reader key needs both the key and its certificate", keyFile, certFile)
	}
	if err := writeFileAtomic(d.instanceFile(name, keyFile), keyPEM); err != nil {
		return err
	}
	return writeFileAtomic(d.instanceFile(name, certFile), certPEM)
}

// PromoteNextReaderKey makes the rotated key the one in use ('farcast reader
// record' after a rotate): it renames reader.key.next over reader.key, then
// reader.crt.next over reader.crt. Both must exist before either moves, so a
// missing certificate never leaves a new key beside the old certificate.
func (d Dir) PromoteNextReaderKey(name string) error {
	for _, f := range []string{nextReaderKeyFile, nextReaderCertFile} {
		if _, err := os.Stat(d.instanceFile(name, f)); err != nil {
			return fmt.Errorf("promote the next reader key: %w", err)
		}
	}
	for _, mv := range [][2]string{{nextReaderKeyFile, readerKeyFile}, {nextReaderCertFile, readerCertFile}} {
		if err := os.Rename(d.instanceFile(name, mv[0]), d.instanceFile(name, mv[1])); err != nil {
			return fmt.Errorf("promote the next reader key: %w", err)
		}
	}
	return nil
}

// LoadReaderKey reads reader.key, the reader's private key.
func (d Dir) LoadReaderKey(name string) ([]byte, error) {
	return readFile(d.instanceFile(name, readerKeyFile))
}

// LoadReaderCert reads reader.crt, the certificate of the reader's key.
func (d Dir) LoadReaderCert(name string) ([]byte, error) {
	return readFile(d.instanceFile(name, readerCertFile))
}

// LoadNextReaderKey reads reader.key.next, a rotated key not yet in use.
func (d Dir) LoadNextReaderKey(name string) ([]byte, error) {
	return readFile(d.instanceFile(name, nextReaderKeyFile))
}

// LoadNextReaderCert reads reader.crt.next, the certificate of a rotated key
// not yet in use: what the rotate script uploads.
func (d Dir) LoadNextReaderCert(name string) ([]byte, error) {
	return readFile(d.instanceFile(name, nextReaderCertFile))
}

// ReaderKeyExists reports whether reader.key exists. It stats the file and
// never opens it, so 'farcast instances' can report a reader's state while
// opening no credential.
func (d Dir) ReaderKeyExists(name string) (bool, error) {
	return statExists(d.instanceFile(name, readerKeyFile))
}

// NextReaderKeyExists reports whether reader.key.next exists, a rotation
// waiting for 'farcast reader record'. It stats the file and never opens it.
func (d Dir) NextReaderKeyExists(name string) (bool, error) {
	return statExists(d.instanceFile(name, nextReaderKeyFile))
}

func statExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// LoadClusterCA reads cluster-ca.crt, the CA a loopback cluster endpoint is
// trusted on. Absent is ok=false and no error: a Google endpoint has none.
func (d Dir) LoadClusterCA(name string) (pem []byte, ok bool, err error) {
	b, err := readFile(d.instanceFile(name, clusterCAFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}
