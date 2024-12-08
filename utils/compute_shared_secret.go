package utils

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/curve25519"
)

/* -------------------------------------------------------------------------- */
/*                             ComputeSharedSecret                            */
/* -------------------------------------------------------------------------- */
// ComputeSharedSecret computes the shared secret using Curve25519's X25519 function.
func ComputeSharedSecret(base64PrivateKey, base64PublicKey string) (string, error) {
	// Decode and validate the private key
	privateKeyBytes, err := DecodeBase64(base64PrivateKey)
	if err != nil {
		return "", err
	}
	if len(privateKeyBytes) != 32 {
		return "", errors.New("private key must be 32 bytes")
	}

	// Decode, validate, and convert the public key
	publicKeyBytes, err := ValidateAndConvertPublicKey(base64PublicKey)
	if err != nil {
		return "", err
	}

	// Compute the shared secret
	sharedSecret, err := curve25519.X25519(privateKeyBytes, publicKeyBytes)
	if err != nil {
		return "", err
	}

	// Return the shared secret as a Base64-encoded string
	return EncodeBase64(sharedSecret), nil
}

/* -------------------------------------------------------------------------- */
/*                         ValidateAndConvertPublicKey                        */
/* -------------------------------------------------------------------------- */
func ValidateAndConvertPublicKey(base64Key string) ([]byte, error) {
	// Decode the Base64 public key
	publicKey, err := DecodeBase64(base64Key)
	if err != nil {
		return nil, err
	}

	// Check if the public key is uncompressed (65 bytes)
	if len(publicKey) == 65 {
		publicKey, err = ExtractCurve25519PublicKey(publicKey)
		if err != nil {
			return nil, err
		}
	}

	// Ensure the key is now 32 bytes
	if len(publicKey) != 32 {
		return nil, errors.New("public key must be 32 bytes after conversion")
	}

	return publicKey, nil
}

/* -------------------------------------------------------------------------- */
/*                         ExtractCurve25519PublicKey                         */
/* -------------------------------------------------------------------------- */
func ExtractCurve25519PublicKey(uncompressedKey []byte) ([]byte, error) {
	if len(uncompressedKey) != 65 || uncompressedKey[0] != 0x04 {
		return nil, errors.New("invalid uncompressed public key format")
	}

	// Extract the X coordinate (32 bytes starting from the second byte)
	return uncompressedKey[1:33], nil
}

/* -------------------------------------------------------------------------- */
/*                      Generate Curve25519 Key Pair                         */
/* -------------------------------------------------------------------------- */
// GenerateCurve25519KeyPair generates a Curve25519 private and public key pair.
func GenerateCurve25519KeyPair() (string, string, error) {
	// Generate a random private key
	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	if err != nil {
		return "", "", err
	}

	// Clamp the private key per the Curve25519 specification
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive the public key using X25519
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}

	// Return the keys as Base64-encoded strings
	return EncodeBase64(privateKey), EncodeBase64(publicKey), nil
}
