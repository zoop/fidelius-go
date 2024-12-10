package utils

import (
	"encoding/base64"
	"errors"
	"math/big"
)

/* -------------------------------------------------------------------------- */
/*                             ComputeSharedSecret                            */
/* -------------------------------------------------------------------------- */
func ComputeSharedSecret(senderPrivateKeyEncoded, requesterPublicKeyEncoded string, curve *Curve) (string, error) {
	// Decode the private key
	senderPrivateKey, err := DecodeBase64ToPrivateKey(senderPrivateKeyEncoded)
	if err != nil {
		return "", err
	}

	// Decode the public key
	requesterPublicKey, err := DecodeBase64ToPublicKey(requesterPublicKeyEncoded, curve)
	if err != nil {
		return "", err
	}

	// Compute the shared secret: (privateKey * publicKey).X
	sharedSecretPoint := requesterPublicKey.ScalarMul(senderPrivateKey)
	return EncodePrivateKeyToBase64(sharedSecretPoint.X), nil
}

func DecodeBase64ToPrivateKey(encodedKey string) (*big.Int, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(keyBytes), nil
}

func DecodeBase64ToPublicKey(encodedKey string, curve *Curve) (*Point, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, err
	}

	var xBytes, yBytes []byte
	if len(keyBytes) == 65 {
		// Ensure the key is in uncompressed form (starts with 0x04)
		if keyBytes[0] != 0x04 {
			return nil, errors.New("invalid public key format")
		}
		xBytes = keyBytes[1:33] // 32 bytes for x-coordinate
		yBytes = keyBytes[33:]  // 32 bytes for y-coordinate
	} else {
		// Assumes x509 format
		xBytes = keyBytes[len(keyBytes)-64 : len(keyBytes)-32]
		yBytes = keyBytes[len(keyBytes)-32:]
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	point, err := NewPoint(x, y, curve)
	return point, err
}
