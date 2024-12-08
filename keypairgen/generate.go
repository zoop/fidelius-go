package keypairgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"

	"github.com/pkg/errors"
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

	privateKeyBase64 := base64.StdEncoding.EncodeToString(privateKey.D.Bytes())

	publicKeyBase64 := k.encodePublicKeyToBase64(publicKey)
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
func (k *keyPairGenHandler) generateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "[ecdsa.GenerateKey][generateKeyPair]")
	}
	return privateKey, &privateKey.PublicKey, nil
}

func (k *keyPairGenHandler) encodePublicKeyToBase64(publicKey *ecdsa.PublicKey) string {
	publicKeyBytes := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)
	return base64.StdEncoding.EncodeToString(publicKeyBytes)
}

/* -------------------------------------------------------------------------- */
/*                         EncodeX509PublicKeyToBase64                        */
/* -------------------------------------------------------------------------- */
func (k *keyPairGenHandler) encodeX509PublicKeyToBase64(publicKey *ecdsa.PublicKey) (string, error) {
	x509Encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", errors.Wrap(err, "[x509.MarshalPKIXPublicKey][encodeX509PublicKeyToBase64]")
	}
	return base64.StdEncoding.EncodeToString(x509Encoded), nil
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
