package decryption

import (
	"testing"

	"github.com/zoop/fidelius-go/encryption"
	"github.com/zoop/fidelius-go/keypairgen"
	"github.com/zoop/fidelius-go/utils"

	"github.com/stretchr/testify/assert"
)

/* -------------------------------------------------------------------------- */
/*                              Tests for Decrypt                             */
/* -------------------------------------------------------------------------- */

func TestDecrypt(t *testing.T) {
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
	encryptionHandler := encryption.Handler()
	senderNonce := utils.GenerateRandomNonce(32)
	assert.NotEmpty(t, senderNonce)
	recieverNone := utils.GenerateRandomNonce(32)
	assert.NotEmpty(t, recieverNone)

	dataToEncrypt := "Hello, World!"
	request := &encryption.EncryptionRequest{
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

	/* ------------------------------ Decrypt Data ------------------------------ */
	decryptionHandler := Handler()
	req := DecryptionRequest{
		EncryptedData:       response.EncryptedData,
		RequesterNonce:      senderNonce,
		SenderNonce:         recieverNone,
		RequesterPrivateKey: keyMaterial.PrivateKey,
		SenderPublicKey:     keyMaterial.PublicKey,
	}
	resp, err := decryptionHandler.Decrypt(req)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp)
	assert.NotEmpty(t, resp.DecryptedData)
	assert.Equal(t, resp.DecryptedData, dataToEncrypt)
}
