// Package secret implements some simple symmetric encryption functions and is shamelessly blagged
// from Vulcand.  See
// https://github.com/vulcand/vulcand/blob/7b479b160401beccbc9521b922588fa2a64c4818/secret/secret.go
package secret

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/stugotech/goconfig"
	"github.com/stugotech/golog"
	"golang.org/x/crypto/nacl/secretbox"
)

var logger = golog.NewPackageLogger()

// config keys
const (
	SealKey = "sealkey"
)

const (
	nonceLength         = 24
	keyLength           = 32
	encryptionSecretBox = "secretbox.v1"
)

// Box represents somewhere to store secrets.
type Box interface {
	Seal(value []byte) ([]byte, error)
	Open(value []byte) ([]byte, error)
}

// box is an implementation of Box.
type box struct {
	key *[32]byte
}

// sealedBytes represents an encrypted value.
type sealedBytes struct {
	Val   []byte
	Nonce []byte
}

// sealedValue is a storage representation of a sealed value.
type sealedValue struct {
	Encryption string
	Value      sealedBytes
}

// NewKeyString generates a new seal key in string format.
func NewKeyString() (string, error) {
	k, err := newKey()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}

// KeyFromString converts a string into a symmetric key.
func KeyFromString(key string) (*[keyLength]byte, error) {
	bytes, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return decodeKey(bytes)
}

// NewBoxFromKeyString creates a secret Box with the given key.
func NewBoxFromKeyString(keyS string) (Box, error) {
	key, err := KeyFromString(keyS)
	if err != nil {
		return nil, err
	}
	return NewBox(key)
}

// NewBoxFromConfig creates a secret box by loading the key from config.
func NewBoxFromConfig(cfg goconfig.Config) (Box, error) {
	key := cfg.GetString(SealKey)
	if key == "" {
		return nil, logger.Error("must specify sealkey")
	}

	box, err := NewBoxFromKeyString(key)
	if err != nil {
		return nil, logger.Errore(err)
	}
	return box, nil
}

// NewBox creates a secret box with the given key.
func NewBox(bytes *[keyLength]byte) (Box, error) {
	return &box{key: bytes}, nil
}

// Seal encrypts a value
func (b *box) Seal(value []byte) ([]byte, error) {
	var nonce [nonceLength]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, logger.Errorex("unable to generate random string", err)
	}
	var encrypted []byte
	encrypted = secretbox.Seal(encrypted[:0], value, &nonce, b.key)

	sealed := &sealedBytes{
		Val:   encrypted,
		Nonce: nonce[:],
	}

	return sealedValueToJSON(sealed)
}

// Open decrypts a value
func (b *box) Open(value []byte) ([]byte, error) {
	e, err := sealedValueFromJSON(value)
	if err != nil {
		return nil, err
	}

	nonce, err := decodeNonce(e.Nonce)
	if err != nil {
		return nil, err
	}
	var decrypted []byte
	var ok bool
	decrypted, ok = secretbox.Open(decrypted[:0], e.Val, nonce, b.key)
	if !ok {
		return nil, logger.Error("unable to decrypt message")
	}
	return decrypted, nil
}

// sealedValueToJSON converts a sealed value to a JSON representation.
func sealedValueToJSON(b *sealedBytes) ([]byte, error) {
	data := &sealedValue{
		Encryption: encryptionSecretBox,
		Value:      *b,
	}
	return json.Marshal(&data)
}

// sealedValueFromJSON converts a JSON representation to a sealed value.
func sealedValueFromJSON(bytes []byte) (*sealedBytes, error) {
	var v *sealedValue
	if err := json.Unmarshal(bytes, &v); err != nil {
		return nil, err
	}
	if v.Encryption != encryptionSecretBox {
		return nil, logger.Error("unsupported encryption type", golog.String("type", v.Encryption))
	}
	return &v.Value, nil
}

func decodeNonce(bytes []byte) (*[nonceLength]byte, error) {
	if len(bytes) != nonceLength {
		return nil, logger.Error("wrong nonce length", golog.Int("length", len(bytes)))
	}
	var nonceBytes [nonceLength]byte
	copy(nonceBytes[:], bytes)
	return &nonceBytes, nil
}

func decodeKey(bytes []byte) (*[keyLength]byte, error) {
	if len(bytes) != keyLength {
		return nil, logger.Error("wrong key length", golog.Int("length", len(bytes)))
	}
	var keyBytes [keyLength]byte
	copy(keyBytes[:], bytes)
	return &keyBytes, nil
}

func newKey() ([]byte, error) {
	var bytes [keyLength]byte
	_, err := io.ReadFull(rand.Reader, bytes[:])
	if err != nil {
		return nil, logger.Errorex("unable to generate random string", err)
	}
	return bytes[:], nil
}
