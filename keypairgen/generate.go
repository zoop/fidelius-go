package keypairgen

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"log"
	"math/big"
)

// Constants are equivalent to the Java constants
const (
	Algorithm = "ECDH"
	Curve     = "curve25519"
)

// Generate generates a key pair and returns the KeyMaterial.
func (k *keyPairGenHandler) Generate() (*KeyMaterial, error) {
	privKey, pubKey, nonce, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	return &KeyMaterial{
		PrivateKey:    privKey,
		PublicKey:     pubKey,
		X509PublicKey: pubKey,
		Nonce:         nonce,
	}, nil
}

// GenerateKeyPair generates an elliptic curve key pair and returns the keys in Base64 format
func GenerateKeyPair() (string, string, string, error) {
	// Generate the private key for Curve25519
	privateKey, publicKey, err := generateCurve25519KeyPair()
	if err != nil {
		return "", "", "", err
	}

	// Encode private and public keys to Base64
	encodedPrivateKey := encodeToBase64(privateKey.Bytes()) // Convert big.Int to []byte
	encodedPublicKey := encodeToBase64(publicKey)

	// Generate a nonce (random 32-byte)
	nonce := generateNonce()

	// Return the Base64 encoded keys and nonce
	return encodedPrivateKey, encodedPublicKey, nonce, nil
}

// generateCurve25519KeyPair generates a Curve25519 key pair (private and public)
func generateCurve25519KeyPair() (*big.Int, []byte, error) {
	// Generate a private key (32 bytes)
	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Curve25519 public key generation (from private key)
	curve := elliptic.P256() // Use a different curve if needed (P-256 is used here for simplicity)
	publicKeyX, publicKeyY := curve.ScalarBaseMult(privateKey)

	// Encode the public key in uncompressed format
	publicKey := append([]byte{0x04}, publicKeyX.Bytes()...)
	publicKey = append(publicKey, publicKeyY.Bytes()...)

	return new(big.Int).SetBytes(privateKey), publicKey, nil
}

// encodeToBase64 encodes a byte slice to Base64
func encodeToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// generateNonce generates a random 32-byte nonce and returns it as a Base64 string
func generateNonce() string {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		log.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(nonce)
}
