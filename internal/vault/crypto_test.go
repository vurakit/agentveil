package vault

import (
	"context"
	"crypto/rand"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("create encryptor: %v", err)
	}

	tests := []string{
		"012345678901",
		"test@example.com",
		"0901234567",
		"Nguyễn Văn A",
		"",
	}

	for _, original := range tests {
		encrypted, err := enc.Encrypt(original)
		if err != nil {
			t.Fatalf("encrypt %q: %v", original, err)
		}

		if original != "" && encrypted == original {
			t.Errorf("encrypted should differ from original for %q", original)
		}

		decrypted, err := enc.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("decrypt %q: %v", original, err)
		}

		if decrypted != original {
			t.Errorf("expected %q, got %q", original, decrypted)
		}
	}
}

func TestEncryptor_WrongKeySize(t *testing.T) {
	_, err := NewEncryptor([]byte("short"))
	if err == nil {
		t.Error("expected error for wrong key size")
	}
}

func TestEncryptor_DifferentCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, _ := NewEncryptor(key)

	// Same plaintext should produce different ciphertexts (random nonce)
	c1, _ := enc.Encrypt("hello")
	c2, _ := enc.Encrypt("hello")

	if c1 == c2 {
		t.Error("same plaintext should produce different ciphertexts")
	}
}

func TestVaultWithEncryption(t *testing.T) {
	v, _ := setupTestVault(t)

	key := make([]byte, 32)
	rand.Read(key)

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	v.SetEncryptor(enc)

	ctx := context.Background()

	// Store encrypted
	mapping := map[string]string{
		"[CCCD_1]": "012345678901",
		"[EMAIL_1]": "test@example.com",
	}
	if err := v.Store(ctx, "enc-session", mapping); err != nil {
		t.Fatalf("store: %v", err)
	}

	// Lookup should decrypt transparently
	got, err := v.LookupAll(ctx, "enc-session")
	if err != nil {
		t.Fatalf("lookupAll: %v", err)
	}

	for token, expected := range mapping {
		if got[token] != expected {
			t.Errorf("token %s: expected %s, got %s", token, expected, got[token])
		}
	}

	// Single lookup
	val, err := v.Lookup(ctx, "enc-session", "[CCCD_1]")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if val != "012345678901" {
		t.Errorf("expected 012345678901, got %s", val)
	}
}
