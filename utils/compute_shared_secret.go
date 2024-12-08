package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"golang.org/x/crypto/curve25519"
)

// Constants are equivalent to the Java constants
const (
	Algorithm = "ECDH"
	Curve     = "curve25519"
)

// DecodeBase64ToBytes decodes a base64 string into a byte array
func DecodeBase64ToBytes(base64Str string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(base64Str)
}

// GenerateECPublicKeyFromBase64Str generates an ECDH public key from a base64-encoded string
func GenerateECPublicKeyFromBase64Str(base64PublicKey string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := DecodeBase64ToBytes(base64PublicKey)
	if err != nil {
		return nil, err
	}

	// Check if the public key starts with 0x04, indicating uncompressed format
	if len(publicKeyBytes) != 65 || publicKeyBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid public key format")
	}

	// Extract x and y coordinates from the public key (after the 0x04 byte)
	x := new(big.Int).SetBytes(publicKeyBytes[1:33])
	y := new(big.Int).SetBytes(publicKeyBytes[33:65])

	// Use Curve25519 for public key
	curve := elliptic.P256() // P256 is used as a placeholder for Curve25519, you may need to replace it with the actual curve

	// Create and return the ECDSA public key
	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return pubKey, nil
}

// GenerateECPrivateKeyFromBase64Str generates an EC private key from a base64-encoded string
func GenerateECPrivateKeyFromBase64Str(base64PrivateKey string) (*ecdsa.PrivateKey, error) {
	privateKeyBytes, err := DecodeBase64ToBytes(base64PrivateKey)
	if err != nil {
		return nil, err
	}

	// Assuming the private key is encoded in a format compatible with the elliptic curve
	// In the case of Curve25519, we will extract it from the base64-encoded string
	privKey := new(big.Int).SetBytes(privateKeyBytes)

	// Generate a private key based on Curve25519 or another curve
	curve := elliptic.P256() // Replace with the correct curve if not using P-256

	// Create the private key on the specified curve (Curve25519 here as an example)
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: privKey,
	}

	// If using curve25519, the private key needs to be converted
	if curve == elliptic.P256() {
		// Do P-256 specific actions here
		return privateKey, nil
	}

	// For Curve25519, we need to convert the private key properly using curve25519 library
	// This is an example with curve25519
	if len(privateKeyBytes) == 32 { // For 256-bit curve25519 private key
		var curve25519PrivKey [32]byte
		copy(curve25519PrivKey[:], privateKeyBytes)
		// Additional handling with curve25519 specific methods
		// Typically, you would use a library or manual conversion for curve25519

		// Example: Generate a corresponding public key (if needed for ECDH)
		// We will skip the public key generation for now as we are focusing on private key generation.
		_ = curve25519PrivKey
	}

	// Return the generated private key
	return privateKey, nil
}

// GenerateX509PublicKeyFromBase64Str generates a public key from a base64 string
func GenerateX509PublicKeyFromBase64Str(base64PublicKey string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := DecodeBase64ToBytes(base64PublicKey)
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaPubKey, nil
}

// ComputeSharedSecret computes the shared secret using the private and public key in base64 encoding
func ComputeSharedSecret(base64PrivateKey, base64PublicKey string) (string, error) {

	privateKey, err := GenerateECPrivateKeyFromBase64Str(base64PrivateKey)
	if err != nil {
		return "", errors.Wrap(err, "[ComputeSharedSecret][x509.ParseECPrivateKey]")
	}

	var publicKey *ecdsa.PublicKey
	if len(base64PublicKey) == 88 {
		// Generate ECDH public key
		publicKey, err = GenerateECPublicKeyFromBase64Str(base64PublicKey)
		if err != nil {
			return "", errors.Wrap(err, "[ComputeSharedSecret][GenerateECPublicKeyFromBase64Str]")
		}
	} else {
		// Generate X509 public key
		publicKey, err = GenerateX509PublicKeyFromBase64Str(base64PublicKey)
		if err != nil {
			return "", errors.Wrap(err, "[ComputeSharedSecret][GenerateX509PublicKeyFromBase64Str]")
		}
	}

	// Using Curve25519 for key exchange
	sharedSecret, err := computeCurve25519SharedSecret(privateKey, publicKey)
	if err != nil {
		return "", errors.Wrap(err, "[ComputeSharedSecret][computeCurve25519SharedSecret]")
	}

	// Return shared secret as Base64
	return base64.StdEncoding.EncodeToString(sharedSecret), nil
}

// computeCurve25519SharedSecret computes a shared secret using Curve25519
func computeCurve25519SharedSecret(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Convert private key to Curve25519 scalar
	privKey := privateKey.D.Bytes()

	// Convert public key to Curve25519 point
	pubKey := publicKey.X.Bytes()

	// Perform Curve25519 ECDH
	var sharedSecret [32]byte
	_, err := curve25519.X25519(privKey, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %v", err)
	}

	return sharedSecret[:], nil
}
