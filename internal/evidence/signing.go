package evidence

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// GenerateSigningKey creates an ed25519 private key and writes it to path
// as PKCS#8 PEM, refusing to overwrite an existing key.
func GenerateSigningKey(path string) (ed25519.PrivateKey, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("signing key %s already exists", path)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("encode signing key: %w", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		return nil, fmt.Errorf("write signing key %s: %w", path, err)
	}
	return priv, nil
}

// LoadSigningKey reads an ed25519 private key from a PKCS#8 PEM file.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path is operator-supplied config
	if err != nil {
		return nil, fmt.Errorf("read signing key %s: %w", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("signing key %s: no PEM block found", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key %s: %w", path, err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key %s: not an ed25519 key", path)
	}
	return priv, nil
}
