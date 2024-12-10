package keypairgen

import (
	"math/big"

	"github.com/zoop/fidelius-go/utils"
)

/* -------------------------------------------------------------------------- */
/*                                  Generate                                  */
/* -------------------------------------------------------------------------- */
// generates a new KeyMaterial with a random private key.
func (k *keyPairGenHandler) Generate() (*KeyMaterial, error) {
	privateKey, err := utils.GeneratePrivateKey(k.Curve)
	if err != nil {
		return nil, err
	}
	publicKeyX, publicKeyY, err := utils.GeneratePublicKey(k.Curve, privateKey)
	if err != nil {
		return nil, err
	}
	return k.encodeKeyMaterial(privateKey, publicKeyX, publicKeyY)
}

/* -------------------------------------------------------------------------- */
/*                            GenerateForPrivateKey                           */
/* -------------------------------------------------------------------------- */
// generates KeyMaterial for a given private key.
func (k *keyPairGenHandler) GenerateForPrivateKey(privateKey *big.Int) (*KeyMaterial, error) {
	publicKeyX, publicKeyY, err := utils.GeneratePublicKey(k.Curve, privateKey)
	if err != nil {
		return nil, err
	}
	return k.encodeKeyMaterial(privateKey, publicKeyX, publicKeyY)
}

/* -------------------------------------------------------------------------- */
/*                              EncodeKeyMaterial                             */
/* -------------------------------------------------------------------------- */
func (k *keyPairGenHandler) encodeKeyMaterial(privateKey *big.Int, publicKeyX, publicKeyY *big.Int) (*KeyMaterial, error) {
	privateKeyBase64 := utils.EncodePrivateKeyToBase64(privateKey)
	publicKeyBase64 := utils.EncodePublicKeyToBase64(publicKeyX, publicKeyY)
	x509PublicKeyBase64, err := utils.EncodeX509PublicKeyToBase64(publicKeyX, publicKeyY)
	if err != nil {
		return nil, err
	}
	nonceBase64 := utils.GenerateBase64Nonce()

	return &KeyMaterial{
		PrivateKey:    privateKeyBase64,
		PublicKey:     publicKeyBase64,
		X509PublicKey: x509PublicKeyBase64,
		Nonce:         nonceBase64,
	}, nil
}
