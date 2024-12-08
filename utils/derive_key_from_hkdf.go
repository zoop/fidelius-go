package utils

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

/* -------------------------------------------------------------------------- */
/*                              DeriveKeyFromHKDF                             */
/* -------------------------------------------------------------------------- */
// deriveKeyFromHKDF derives a key using HKDF with the given salt and secret.
func DeriveKeyFromHKDF(salt []byte, secret string, length int) []byte {
	hkdf := hkdf.New(sha256.New, []byte(secret), salt, nil)
	key := make([]byte, length)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key
}
