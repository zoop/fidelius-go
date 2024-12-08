package keypairgen

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/pkg/errors"
	"golang.org/x/crypto/curve25519"
)

/* -------------------------------------------------------------------------- */
/*                                  Generate                                  */
/* -------------------------------------------------------------------------- */
func (k *keyPairGenHandler) Generate() (*KeyMaterial, error) {
	var keyMaterial *KeyMaterial
	var err error

	privateKey, publicKey, err := k.generateKeyPair()
	if err != nil {
		return keyMaterial, errors.Wrap(err, "[generateKeyPair][Generate]")
	}

	privateKeyBase64 := base64.StdEncoding.EncodeToString(privateKey)

	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)
	x509PublicKeyBase64, err := k.encodeX509PublicKeyToBase64(publicKey)
	if err != nil {
		return keyMaterial, errors.Wrap(err, "[encodeX509PublicKeyToBase64][Generate]")
	}

	nonce, err := k.generateNonce()
	if err != nil {
		return keyMaterial, errors.Wrap(err, "[generateNonce][Generate]")
	}
	keyMaterial = &KeyMaterial{
		PrivateKey:    privateKeyBase64,
		PublicKey:     publicKeyBase64,
		X509PublicKey: x509PublicKeyBase64,
		Nonce:         nonce,
	}
	return keyMaterial, nil
}

/* -------------------------------------------------------------------------- */
/*                               GenerateKeyPair                              */
/* -------------------------------------------------------------------------- */
func (k *keyPairGenHandler) generateKeyPair() ([]byte, []byte, error) {
	// Generate a random 32-byte private key for Curve25519
	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "[rand.Read][generateKeyPair]")
	}

	// Generate the public key from the private key
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, errors.Wrap(err, "[curve25519.X25519][generateKeyPair]")
	}

	return privateKey, publicKey, nil
}

/* -------------------------------------------------------------------------- */
/*                         EncodeX509PublicKeyToBase64                        */
/* -------------------------------------------------------------------------- */
func (k *keyPairGenHandler) encodeX509PublicKeyToBase64(publicKey []byte) (string, error) {
	// Since Curve25519 doesn't use traditional X.509 encoding for public keys,
	// we will use the raw public key for encoding.
	return base64.StdEncoding.EncodeToString(publicKey), nil
}

/* -------------------------------------------------------------------------- */
/*                                GenerateNonce                               */
/* -------------------------------------------------------------------------- */
func (k *keyPairGenHandler) generateNonce() (string, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", errors.Wrap(err, "[rand.Read][generateNonce]")
	}
	return base64.StdEncoding.EncodeToString(nonce), nil
}
