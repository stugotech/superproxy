package store

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"crypto/sha1"
	"encoding/hex"
)

// parsePrivateKeyFromDER attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKeyFromDER(der []byte) (crypto.Signer, error) {
	// from https://golang.org/src/crypto/tls/tls.go
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, logger.Error("found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, logger.Error("failed to parse private key")
}

// createKey creates a new encryption key and returns as a crypto.Signer and DER encoded form.
func createKey() (crypto.Signer, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, logger.Errore(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, logger.Errore(err)
	}
	return key, der, nil
}

// thumbprint gets the string thumbprint for a certificate.
func thumbprint(der []byte) string {
	thumbprint := sha1.Sum(der)
	return hex.EncodeToString(thumbprint[:])
}
