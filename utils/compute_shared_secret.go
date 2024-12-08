package utils

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
)

type PublicKey struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

/* -------------------------------------------------------------------------- */
/*                             ComputeSharedSecret                            */
/* -------------------------------------------------------------------------- */
// computeSharedSecret computes the shared secret using ECDH.
func ComputeSharedSecret(base64PrivateKey, base64PublicKey string) (string, error) {
	var sharedSecret []byte

	// Decode the private key
	privateKeyBytes, err := DecodeBase64(base64PrivateKey)
	if err != nil {
		return "", err
	}

	privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return "", err
	}

	// Decode the public key
	publicKeyBytes, err := DecodeBase64(base64PublicKey)
	if err != nil {
		return "", err
	}

	publicKey, err := ecdh.P256().NewPublicKey(publicKeyBytes)
	if err != nil {
		return "", err
	}

	// Compute the shared secret
	sharedSecret, err = privateKey.ECDH(publicKey)
	if err != nil {
		return "", err
	}

	// Return the shared secret as a Base64-encoded string
	return EncodeBase64(sharedSecret), nil
}

func DecodeECPrivateKeyFromBase64(base64PrivateKey string) (*PrivateKey, error) {
	var privateKey *PrivateKey
	privateKeyBytes, err := DecodeBase64(base64PrivateKey)
	if err != nil {
		return privateKey, err
	}

	d := new(big.Int).SetBytes(privateKeyBytes)

	curve := elliptic.P256()
	privateKey = &PrivateKey{
		D: d,
		PublicKey: PublicKey{
			Curve: curve,
			X:     nil,
			Y:     nil,
		},
	}
	return privateKey, nil
}
