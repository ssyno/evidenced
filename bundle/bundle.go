// Package bundle defines the export bundle format — evidence.json,
// report.md and a checksummed, optionally ed25519-signed manifest — and
// the verification any third party (auditor, portal) can run on it.
package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ssyno/evidenced/evidence"
)

// Header is the structure of evidence.json.
type Header struct {
	Tool        string            `json:"tool"`
	Framework   string            `json:"framework"`
	GeneratedAt time.Time         `json:"generatedAt"`
	RecordCount int               `json:"recordCount"`
	Records     []evidence.Record `json:"records"`
}

// Manifest is the structure of manifest.json.
type Manifest struct {
	GeneratedAt time.Time         `json:"generatedAt"`
	Files       map[string]string `json:"files"`               // name -> sha256 hex
	PublicKey   string            `json:"publicKey,omitempty"` // base64 ed25519
	Signature   string            `json:"signature,omitempty"` // base64 over canonical files JSON
}

// Signed reports whether the manifest carries a signature.
func (m Manifest) Signed() bool { return m.Signature != "" }

// BuildManifest checksums the given files and, with a key, signs the
// canonical checksum list.
func BuildManifest(files map[string][]byte, key ed25519.PrivateKey, now time.Time) (Manifest, error) {
	man := Manifest{GeneratedAt: now, Files: map[string]string{}}
	for name, content := range files {
		sum := sha256.Sum256(content)
		man.Files[name] = hex.EncodeToString(sum[:])
	}
	if key != nil {
		signed, err := json.Marshal(man.Files)
		if err != nil {
			return Manifest{}, fmt.Errorf("encode manifest for signing: %w", err)
		}
		man.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, signed))
		man.PublicKey = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	}
	return man, nil
}

// Verify recomputes the checksums in a bundle directory's manifest and,
// when the manifest is signed, verifies the signature.
func Verify(dir string) error {
	man, err := ReadManifest(dir)
	if err != nil {
		return err
	}
	for name, want := range man.Files {
		content, err := os.ReadFile(filepath.Join(dir, filepath.Base(name))) // #nosec G304 -- caller-chosen bundle dir
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		sum := sha256.Sum256(content)
		if got := hex.EncodeToString(sum[:]); got != want {
			return fmt.Errorf("checksum mismatch for %s: manifest %s, file %s", name, want, got)
		}
	}
	if man.Signature != "" {
		pub, err := base64.StdEncoding.DecodeString(man.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("manifest has invalid public key")
		}
		sig, err := base64.StdEncoding.DecodeString(man.Signature)
		if err != nil {
			return fmt.Errorf("manifest has invalid signature encoding")
		}
		signed, err := json.Marshal(man.Files)
		if err != nil {
			return fmt.Errorf("encode manifest files: %w", err)
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), signed, sig) {
			return fmt.Errorf("manifest signature verification failed")
		}
	}
	return nil
}

// ReadManifest loads and parses manifest.json from a bundle directory.
func ReadManifest(dir string) (Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json")) // #nosec G304 -- caller-chosen bundle dir
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var man Manifest
	if err := json.Unmarshal(b, &man); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	return man, nil
}

// Read loads evidence.json from a bundle directory and additionally
// verifies the records' hash chain.
func Read(dir string) (*Header, error) {
	b, err := os.ReadFile(filepath.Join(dir, "evidence.json")) // #nosec G304 -- caller-chosen bundle dir
	if err != nil {
		return nil, fmt.Errorf("read evidence.json: %w", err)
	}
	var h Header
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("parse evidence.json: %w", err)
	}
	if err := evidence.Verify(h.Records); err != nil {
		return nil, fmt.Errorf("evidence chain: %w", err)
	}
	return &h, nil
}
