package encryption

import (
	"testing"

	"github.com/zoop/fidelius-go/keypairgen"
	"github.com/zoop/fidelius-go/utils"

	"github.com/stretchr/testify/assert"
)

/* -------------------------------------------------------------------------- */
/*                              Tests for Encrypt                             */
/* -------------------------------------------------------------------------- */

func TestEncrypt(t *testing.T) {

	/* -------------------------- Generate Keypair Gen -------------------------- */
	BC25519, err := utils.GetBC25519Curve()
	assert.NoError(t, err)
	handler := keypairgen.Handler(BC25519)
	keyMaterial, err := handler.Generate()
	assert.NoError(t, err)

	assert.NotEmpty(t, keyMaterial.Nonce)
	assert.NotEmpty(t, keyMaterial.PrivateKey)
	assert.NotEmpty(t, keyMaterial.PublicKey)
	assert.NotEmpty(t, keyMaterial.X509PublicKey)

	/* -------------------------- Compute Shared Secret ------------------------- */
	sharedSecret, err := utils.ComputeSharedSecret(keyMaterial.PrivateKey, keyMaterial.PublicKey, BC25519)
	assert.NoError(t, err)
	assert.NotEmpty(t, sharedSecret)

	/* ------------------------------ Encrypt Data ------------------------------ */
	encryptionHandler := Handler(BC25519)
	senderNonce := utils.GenerateRandomNonce(32)
	assert.NotEmpty(t, senderNonce)
	recieverNone := utils.GenerateRandomNonce(32)
	assert.NotEmpty(t, recieverNone)

	dataToEncrypt := "Hello, World!"
	request := EncryptionRequest{
		StringToEncrypt:    dataToEncrypt,
		SenderNonce:        senderNonce,
		RequesterNonce:     recieverNone,
		SenderPrivateKey:   keyMaterial.PrivateKey,
		RequesterPublicKey: keyMaterial.PublicKey,
	}
	response, err := encryptionHandler.Encrypt(request)
	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	assert.NotEmpty(t, response)
}
