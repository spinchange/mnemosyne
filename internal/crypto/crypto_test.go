package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	password := []byte("password123")
	salt := []byte("saltsaltsaltsalt")
	m, time, p := uint32(1024), uint32(1), uint8(1)

	dataKey, _, _ := DeriveKeys(password, salt, m, time, p)
	plaintext := []byte("hello mnemosyne")
	aad := []byte("aad-context")

	envelope, err := Encrypt(dataKey, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(dataKey, envelope, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted data doesn't match plaintext: got %s, want %s", decrypted, plaintext)
	}
}

func TestWrongKeyFails(t *testing.T) {
	password := []byte("password123")
	wrongPassword := []byte("wrongpassword")
	salt := []byte("saltsaltsaltsalt")
	m, time, p := uint32(1024), uint32(1), uint8(1)

	dataKey, _, _ := DeriveKeys(password, salt, m, time, p)
	wrongKey, _, _ := DeriveKeys(wrongPassword, salt, m, time, p)
	
	plaintext := []byte("sensitive info")
	aad := []byte("context")

	envelope, _ := Encrypt(dataKey, plaintext, aad)

	_, err := Decrypt(wrongKey, envelope, aad)
	if err != ErrDecryptFailed {
		t.Errorf("Decrypt with wrong key should return ErrDecryptFailed, got %v", err)
	}
}

func TestWrongAADFails(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("data")
	aad := []byte("aad1")
	wrongAAD := []byte("aad2")

	envelope, _ := Encrypt(key, plaintext, aad)

	_, err := Decrypt(key, envelope, wrongAAD)
	if err != ErrDecryptFailed {
		t.Errorf("Decrypt with wrong AAD should fail, got %v", err)
	}
}

func TestCiphertextTransplantFails(t *testing.T) {
	key := make([]byte, 32)
	plaintext1 := []byte("field1")
	aad1 := []byte("context:field1")
	aad2 := []byte("context:field2")

	envelope1, _ := Encrypt(key, plaintext1, aad1)

	// Try to decrypt envelope1 using aad2
	_, err := Decrypt(key, envelope1, aad2)
	if err != ErrDecryptFailed {
		t.Errorf("Ciphertext transplant should fail due to AAD mismatch, got %v", err)
	}
}

func TestNonceUniqueness(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("the same data")
	aad := []byte("context")

	env1, _ := Encrypt(key, plaintext, aad)
	env2, _ := Encrypt(key, plaintext, aad)

	if bytes.Equal(env1, env2) {
		t.Errorf("Two encryptions of same data should have different nonces")
	}
}
