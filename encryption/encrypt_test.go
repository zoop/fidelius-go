package encryption

import (
	"fidelius-go/keypairgen"
	"fidelius-go/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

/* -------------------------------------------------------------------------- */
/*                              Tests for Encrypt                             */
/* -------------------------------------------------------------------------- */

func TestEncrypt(t *testing.T) {
	/* -------------------------- Generate Keypair Gen -------------------------- */
	handler := keypairgen.Handler()
	keyMaterial, err := handler.Generate()
	assert.NoError(t, err)

	assert.NotEmpty(t, keyMaterial.Nonce)
	assert.NotEmpty(t, keyMaterial.PrivateKey)
	assert.NotEmpty(t, keyMaterial.PublicKey)
	assert.NotEmpty(t, keyMaterial.X509PublicKey)

	/* -------------------------- Compute Shared Secret ------------------------- */
	sharedSecret, err := utils.ComputeSharedSecret(keyMaterial.PrivateKey, keyMaterial.PublicKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, sharedSecret)

	/* ------------------------------ Encrypt Data ------------------------------ */
	encryptionHandler := Handler()
	senderNonce := utils.GenerateRandomNonce(32)
	assert.NotEmpty(t, senderNonce)
	recieverNone := utils.GenerateRandomNonce(32)
	assert.NotEmpty(t, recieverNone)

	dataToEncrypt := "Hello, World!"
	request := &EncryptionRequest{
		StringToEncrypt:    dataToEncrypt,
		SenderNonce:        senderNonce,
		RequesterNonce:     recieverNone,
		SenderPrivateKey:   keyMaterial.PrivateKey,
		RequesterPublicKey: keyMaterial.PublicKey,
	}
	response, err := encryptionHandler.Encrypt(request)
	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	assert.NotEmpty(t, response.EncryptedData)
}
