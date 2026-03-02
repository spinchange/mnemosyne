package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	Version1  = 0x01
	NonceSize = 12
)

var (
	ErrDecryptFailed   = errors.New("decryption failed: data may be corrupted or wrong key")
	ErrInvalidVersion  = errors.New("invalid encryption version")
	ErrInvalidEnvelope = errors.New("invalid encryption envelope")
)

// DeriveKeys derives a data key and a verify key from a password and salt using Argon2id and HKDF.
func DeriveKeys(password []byte, salt []byte, m, t uint32, p uint8) (dataKey []byte, verifyKey []byte, err error) {
	// 1. Run Argon2id
	masterKey := argon2.IDKey(password, salt, t, m, p, 32)
	defer Zero(masterKey)

	// 2. Use HKDF to derive subkeys
	dataKey = make([]byte, 32)
	verifyKey = make([]byte, 32)

	dataHKDF := hkdf.New(sha256.New, masterKey, nil, []byte("mnemosyne-data-v1"))
	verifyHKDF := hkdf.New(sha256.New, masterKey, nil, []byte("mnemosyne-verify-v1"))

	if _, err := io.ReadFull(dataHKDF, dataKey); err != nil {
		Zero(dataKey)
		Zero(verifyKey)
		return nil, nil, fmt.Errorf("derive data key: %w", err)
	}
	if _, err := io.ReadFull(verifyHKDF, verifyKey); err != nil {
		Zero(dataKey)
		Zero(verifyKey)
		return nil, nil, fmt.Errorf("derive verify key: %w", err)
	}

	return dataKey, verifyKey, nil
}

// Encrypt encrypts plaintext using AES-256-GCM and returns a versioned envelope.
func Encrypt(key []byte, plaintext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Include version byte in AAD for authentication
	authenticatedAAD := make([]byte, 1+len(aad))
	authenticatedAAD[0] = Version1
	copy(authenticatedAAD[1:], aad)
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, authenticatedAAD)

	// Envelope: [ version: 1 byte | nonce: 12 bytes | ciphertext+tag: N bytes ]
	envelope := make([]byte, 1+NonceSize+len(ciphertext))
	envelope[0] = Version1
	copy(envelope[1:1+NonceSize], nonce)
	copy(envelope[1+NonceSize:], ciphertext)

	return envelope, nil
}

// Decrypt decrypts a versioned envelope using AES-256-GCM.
func Decrypt(key []byte, envelope []byte, aad []byte) ([]byte, error) {
	if len(envelope) < 1+NonceSize {
		return nil, ErrInvalidEnvelope
	}

	version := envelope[0]
	if version != Version1 {
		return nil, ErrInvalidVersion
	}

	nonce := envelope[1 : 1+NonceSize]
	ciphertext := envelope[1+NonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aesgcm.Overhead() {
		return nil, ErrInvalidEnvelope
	}

	// Include version byte in AAD for authentication
	authenticatedAAD := make([]byte, 1+len(aad))
	authenticatedAAD[0] = version
	copy(authenticatedAAD[1:], aad)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, authenticatedAAD)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return plaintext, nil
}

// Zero explicitly clears a byte slice to minimize its lifetime in memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// FormatAAD constructs the AAD string for a given context.
func FormatAAD(table, field string, rowID int64) []byte {
	return []byte(fmt.Sprintf("mnemosyne:v1:%s:%s:%d", table, field, rowID))
}

