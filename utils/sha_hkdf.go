package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
)

/* -------------------------------------------------------------------------- */
/*                                    HKDF                                    */
/* -------------------------------------------------------------------------- */
// HKDF derives one key from a master secret using the HMAC-based KDF defined in RFC 5869.
func HKDF(master []byte, keyLen int, salt []byte, hashmod func() hash.Hash, numKeys int, context []byte) ([]byte, error) {
	// Output length must be within bounds
	outputLen := keyLen * numKeys
	if outputLen > (255 * hashmod().Size()) {
		return nil, errors.New("Too much secret data to derive")
	}

	// Step 1: Extract
	if len(salt) == 0 {
		salt = make([]byte, hashmod().Size())
	}
	hmacInstance := hmac.New(hashmod, salt)
	hmacInstance.Write(master)
	prk := hmacInstance.Sum(nil)

	// Step 2: Expand
	var t []byte
	n := 1
	tLen := 0
	var derivedOutput []byte

	for tLen < outputLen {
		hmacInstance = hmac.New(hashmod, prk)
		hmacInstance.Write(t)
		hmacInstance.Write(context)
		hmacInstance.Write([]byte{byte(n)})
		t = hmacInstance.Sum(nil)
		derivedOutput = append(derivedOutput, t...)
		tLen += hashmod().Size()
		n++
	}

	// If numKeys is 1, return a single key
	if numKeys == 1 {
		return derivedOutput[:keyLen], nil
	}

	// Otherwise, return multiple keys
	var kol [][]byte
	for i := 0; i < numKeys; i++ {
		start := i * keyLen
		end := start + keyLen
		if end > len(derivedOutput) {
			end = len(derivedOutput)
		}
		kol = append(kol, derivedOutput[start:end])
	}

	// In case numKeys is greater than 1, return the array of keys
	return kol[0], nil
}

/* -------------------------------------------------------------------------- */
/*                                 sha256Hkdf                                 */
/* -------------------------------------------------------------------------- */
// sha256Hkdf is the function that decodes the shared secret from base64 and performs HKDF.
func Sha256HKDF(salt []byte, sharedSecret string, keyLengthInBytes int) ([]byte, error) {
	// Decode the shared secret from Base64
	sharedSecretBytes, err := base64.StdEncoding.DecodeString(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("error decoding shared secret: %v %s", err, sharedSecret)
	}

	// Perform HKDF using SHA-256
	encryptionKey, err := HKDF(sharedSecretBytes, keyLengthInBytes, salt, sha256.New, 1, nil)
	if err != nil {
		return nil, fmt.Errorf("error deriving encryption key: %v", err)
	}

	return encryptionKey, nil
}
