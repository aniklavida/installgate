package quarantine

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
)

var (
	ErrInvalidDigestFormat     = errors.New("invalid digest format: expected SRI or hex shasum")
	ErrUnsupportedAlgorithm    = errors.New("unsupported digest algorithm")
	ErrIntegrityMismatch       = errors.New("integrity verification failed: digest mismatch")
	ErrIntegrityMismatchSecond = errors.New("second integrity verification failed: blob modified between inspection and release")
)

// ParsedDigest represents a verified cryptographic digest with its algorithm,
// hex representation, canonical SRI string, and content-addressable key.
type ParsedDigest struct {
	Algorithm string // sha512, sha384, sha256, sha1
	Hex       string // lower-case hex representation
	SRI       string // canonical SRI: "<algo>-<base64>"
	Bytes     []byte // raw digest bytes
}

// Key returns a canonical, filesystem-safe content-addressed blob key.
func (d ParsedDigest) Key() string {
	return d.Algorithm + "-" + d.Hex
}

// ParseDigest normalizes and validates an SRI or hex digest string.
func ParseDigest(raw string) (ParsedDigest, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedDigest{}, ErrInvalidDigestFormat
	}

	// Case 1: Prefixed format: <algorithm>-<base64_or_hex>
	if dashIdx := strings.Index(trimmed, "-"); dashIdx > 0 {
		algo := strings.ToLower(trimmed[:dashIdx])
		encoded := trimmed[dashIdx+1:]

		expectedLen, err := expectedDigestByteLen(algo)
		if err != nil {
			return ParsedDigest{}, err
		}

		// First, check if encoded is a valid hex representation
		if hexBytes, err := hex.DecodeString(encoded); err == nil && len(hexBytes) == expectedLen {
			hexStr := strings.ToLower(encoded)
			canonicalSRI := algo + "-" + base64.StdEncoding.EncodeToString(hexBytes)
			return ParsedDigest{
				Algorithm: algo,
				Hex:       hexStr,
				SRI:       canonicalSRI,
				Bytes:     hexBytes,
			}, nil
		}

		// Second, try base64 standard / raw url decoding (SRI format)
		rawBytes, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			rawBytes, err = base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				return ParsedDigest{}, fmt.Errorf("%w: invalid digest encoding", ErrInvalidDigestFormat)
			}
		}

		if len(rawBytes) != expectedLen {
			return ParsedDigest{}, fmt.Errorf("%w: digest length %d does not match algorithm %s (%d bytes)",
				ErrInvalidDigestFormat, len(rawBytes), algo, expectedLen)
		}

		hexStr := hex.EncodeToString(rawBytes)
		canonicalSRI := algo + "-" + base64.StdEncoding.EncodeToString(rawBytes)

		return ParsedDigest{
			Algorithm: algo,
			Hex:       hexStr,
			SRI:       canonicalSRI,
			Bytes:     rawBytes,
		}, nil
	}

	// Case 2: Hex string (legacy npm shasum or direct hex digest)
	hexBytes, err := hex.DecodeString(trimmed)
	if err != nil {
		return ParsedDigest{}, fmt.Errorf("%w: invalid hex encoding", ErrInvalidDigestFormat)
	}

	var algo string
	switch len(hexBytes) {
	case 20:
		algo = "sha1"
	case 32:
		algo = "sha256"
	case 48:
		algo = "sha384"
	case 64:
		algo = "sha512"
	default:
		return ParsedDigest{}, fmt.Errorf("%w: unrecognized hex digest length %d", ErrInvalidDigestFormat, len(hexBytes))
	}

	hexStr := strings.ToLower(trimmed)
	canonicalSRI := algo + "-" + base64.StdEncoding.EncodeToString(hexBytes)

	return ParsedDigest{
		Algorithm: algo,
		Hex:       hexStr,
		SRI:       canonicalSRI,
		Bytes:     hexBytes,
	}, nil
}

func expectedDigestByteLen(algo string) (int, error) {
	switch algo {
	case "sha512":
		return 64, nil
	case "sha384":
		return 48, nil
	case "sha256":
		return 32, nil
	case "sha1":
		return 20, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, algo)
	}
}

// HasherFor returns a new hash.Hash instance for the specified algorithm.
func HasherFor(algo string) (hash.Hash, error) {
	switch strings.ToLower(algo) {
	case "sha512":
		return sha512.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha1":
		return sha1.New(), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, algo)
	}
}

// ComputeDigest reads stream r to completion and calculates its ParsedDigest using algo.
func ComputeDigest(algo string, r io.Reader) (ParsedDigest, error) {
	hasher, err := HasherFor(algo)
	if err != nil {
		return ParsedDigest{}, err
	}

	if _, err := io.Copy(hasher, r); err != nil {
		return ParsedDigest{}, fmt.Errorf("failed computing digest: %w", err)
	}

	digestBytes := hasher.Sum(nil)
	hexStr := hex.EncodeToString(digestBytes)
	sri := strings.ToLower(algo) + "-" + base64.StdEncoding.EncodeToString(digestBytes)

	return ParsedDigest{
		Algorithm: strings.ToLower(algo),
		Hex:       hexStr,
		SRI:       sri,
		Bytes:     digestBytes,
	}, nil
}

// VerifyDigest streams r and compares the computed digest against expected.
// It returns whether the digests match, the computed digest, and any read/format error.
func VerifyDigest(expected string, r io.Reader) (bool, ParsedDigest, error) {
	parsedExpected, err := ParseDigest(expected)
	if err != nil {
		return false, ParsedDigest{}, err
	}

	computed, err := ComputeDigest(parsedExpected.Algorithm, r)
	if err != nil {
		return false, ParsedDigest{}, err
	}

	matches := bytes.Equal(parsedExpected.Bytes, computed.Bytes)
	return matches, computed, nil
}
