package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// DecodeBase64ToBytes decodes a base64 string to bytes
func DecodeBase64ToBytes(base64Str string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(base64Str)
}

// GenerateSharedSecret computes the shared secret using Curve25519
func ComputeSharedSecret(privateKeyBase64, publicKeyBase64 string) (string, error) {
	// Decode the base64-encoded keys
	privKeyBytes, err := DecodeBase64ToBytes(privateKeyBase64)
	if err != nil {
		return "", err
	}
	pubKeyBytes, err := DecodeBase64ToBytes(publicKeyBase64)
	if err != nil {
		return "", err
	}

	// Ensure the private key and public key lengths are correct for Curve25519
	if len(privKeyBytes) != 32 || len(pubKeyBytes) != 32 {
		return "", errors.New("invalid key length for Curve25519")
	}

	// Convert the private key to a Curve25519 scalar
	privKey := [32]byte{}
	copy(privKey[:], privKeyBytes)

	// Convert the public key to a Curve25519 point
	pubKey := [32]byte{}
	copy(pubKey[:], pubKeyBytes)

	// Compute the shared secret using Curve25519
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &privKey, &pubKey)

	// Optionally, hash the shared secret using SHA-256 (e.g., HKDF could be used here)
	sha256Hash := sha256.New()
	sha256Hash.Write(sharedSecret[:])
	sharedSecretHash := sha256Hash.Sum(nil)

	// Return the shared secret as a base64 string
	return base64.StdEncoding.EncodeToString(sharedSecretHash), nil
}
