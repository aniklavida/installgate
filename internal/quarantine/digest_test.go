package quarantine

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestParseDigest_SRI(t *testing.T) {
	data := []byte("sample tarball payload")

	// sha512
	h512 := sha512.Sum512(data)
	sri512 := "sha512-" + base64.StdEncoding.EncodeToString(h512[:])
	d512, err := ParseDigest(sri512)
	if err != nil {
		t.Fatalf("ParseDigest(sha512) failed: %v", err)
	}
	if d512.Algorithm != "sha512" {
		t.Errorf("Algorithm = %q, want sha512", d512.Algorithm)
	}
	if d512.Hex != hex.EncodeToString(h512[:]) {
		t.Errorf("Hex = %q, want %q", d512.Hex, hex.EncodeToString(h512[:]))
	}
	if d512.SRI != sri512 {
		t.Errorf("SRI = %q, want %q", d512.SRI, sri512)
	}
	if d512.Key() != "sha512-"+hex.EncodeToString(h512[:]) {
		t.Errorf("Key() = %q, want %q", d512.Key(), "sha512-"+hex.EncodeToString(h512[:]))
	}

	// sha256
	h256 := sha256.Sum256(data)
	sri256 := "sha256-" + base64.StdEncoding.EncodeToString(h256[:])
	d256, err := ParseDigest(sri256)
	if err != nil {
		t.Fatalf("ParseDigest(sha256) failed: %v", err)
	}
	if d256.Algorithm != "sha256" {
		t.Errorf("Algorithm = %q, want sha256", d256.Algorithm)
	}

	// sha1
	h1 := sha1.Sum(data)
	sri1 := "sha1-" + base64.StdEncoding.EncodeToString(h1[:])
	d1, err := ParseDigest(sri1)
	if err != nil {
		t.Fatalf("ParseDigest(sha1) failed: %v", err)
	}
	if d1.Algorithm != "sha1" {
		t.Errorf("Algorithm = %q, want sha1", d1.Algorithm)
	}
}

func TestParseDigest_Hex(t *testing.T) {
	data := []byte("sample tarball payload")

	// 40 chars = sha1
	h1 := sha1.Sum(data)
	hex1 := hex.EncodeToString(h1[:])
	d1, err := ParseDigest(hex1)
	if err != nil {
		t.Fatalf("ParseDigest(hex sha1) failed: %v", err)
	}
	if d1.Algorithm != "sha1" {
		t.Errorf("Algorithm = %q, want sha1", d1.Algorithm)
	}
	if d1.Hex != hex1 {
		t.Errorf("Hex = %q, want %q", d1.Hex, hex1)
	}

	// 64 chars = sha256
	h256 := sha256.Sum256(data)
	hex256 := hex.EncodeToString(h256[:])
	d256, err := ParseDigest(hex256)
	if err != nil {
		t.Fatalf("ParseDigest(hex sha256) failed: %v", err)
	}
	if d256.Algorithm != "sha256" {
		t.Errorf("Algorithm = %q, want sha256", d256.Algorithm)
	}

	// 128 chars = sha512
	h512 := sha512.Sum512(data)
	hex512 := hex.EncodeToString(h512[:])
	d512, err := ParseDigest(hex512)
	if err != nil {
		t.Fatalf("ParseDigest(hex sha512) failed: %v", err)
	}
	if d512.Algorithm != "sha512" {
		t.Errorf("Algorithm = %q, want sha512", d512.Algorithm)
	}
}

func TestParseDigest_Errors(t *testing.T) {
	invalidCases := []string{
		"",
		"   ",
		"md5-xyz",
		"sha512-invalidBase64!!",
		"sha512-short",
		"not-a-hash",
		"12345", // invalid hex length
	}

	for _, tc := range invalidCases {
		_, err := ParseDigest(tc)
		if err == nil {
			t.Errorf("ParseDigest(%q) expected error, got nil", tc)
		}
	}
}

func TestVerifyDigest(t *testing.T) {
	content := []byte("hello world npm tarball")
	h512 := sha512.Sum512(content)
	expectedSRI := "sha512-" + base64.StdEncoding.EncodeToString(h512[:])

	// Correct match
	matches, computed, err := VerifyDigest(expectedSRI, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("VerifyDigest failed: %v", err)
	}
	if !matches {
		t.Errorf("expected matches = true, got false")
	}
	if computed.Hex != hex.EncodeToString(h512[:]) {
		t.Errorf("computed hex = %q, want %q", computed.Hex, hex.EncodeToString(h512[:]))
	}

	// Mismatch
	corrupted := []byte("hello world npm tarball - tampered")
	matches, _, err = VerifyDigest(expectedSRI, bytes.NewReader(corrupted))
	if err != nil {
		t.Fatalf("VerifyDigest with corrupted data failed: %v", err)
	}
	if matches {
		t.Errorf("expected matches = false for corrupted content, got true")
	}

	// Invalid expected SRI string
	_, _, err = VerifyDigest("invalid-digest", bytes.NewReader(content))
	if err == nil {
		t.Errorf("expected error for invalid digest string")
	}
}
