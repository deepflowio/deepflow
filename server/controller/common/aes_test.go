package common

import (
	"fmt"
	"testing"
)

func TestAesDecrypt(t *testing.T) {
	// Test data
	origData := "Hello, World!"
	key := "1234567890123456" // 16 bytes for AES-128

	// Encrypt first
	encrypted, err := AesEncrypt(origData, key)
	if err != nil {
		t.Fatalf("AesEncrypt failed: %v", err)
	}
	fmt.Printf("Encrypted data: %s\n", encrypted)

	// Now decrypt
	decrypted, err := AesDecrypt(encrypted, key)
	if err != nil {
		t.Fatalf("AesDecrypt failed: %v", err)
	}
	fmt.Printf("Decrypted data: %s\n", decrypted)

	if decrypted != origData {
		t.Errorf("Expected %s, got %s", origData, decrypted)
	}
}

func TestDerivePBKDF2Key(t *testing.T) {
	userID := 1
	orgID := 1

	key := DerivePBKDF2Key(userID, orgID)
	fmt.Printf("Derived key: %x\n", key)

	// Check length
	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Test with different inputs
	key2 := DerivePBKDF2Key(2, 1)
	fmt.Printf("Derived key2: %x\n", key2)

	if string(key) == string(key2) {
		t.Errorf("Keys should be different for different userIDs")
	}
}
