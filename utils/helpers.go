package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

/* -------------------------------------------------------------------------- */
/*                             GenerateRandomNonce                            */
/* -------------------------------------------------------------------------- */
func GenerateRandomNonce(size int) string {
	nonce := make([]byte, size)
	_, err := rand.Read(nonce)
	if err != nil {
		panic("failed to generate random nonce")
	}
	return EncodeBase64(nonce)
}

/* -------------------------------------------------------------------------- */
/*                                  DeriveKey                                 */
/* -------------------------------------------------------------------------- */
func DeriveKey(salt []byte, sharedSecret string, keyLength int) []byte {
	hkdf := hkdf.New(sha256.New, []byte(sharedSecret), salt, nil)
	key := make([]byte, keyLength)
	_, err := io.ReadFull(hkdf, key)
	if err != nil {
		panic("failed to derive key using HKDF")
	}
	return key
}
