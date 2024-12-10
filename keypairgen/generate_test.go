package keypairgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zoop/fidelius-go/utils"
)

/* -------------------------------------------------------------------------- */
/*                           Tests for GenerateTest                           */
/* -------------------------------------------------------------------------- */
func TestGenerateTest(t *testing.T) {
	BC25519, err := utils.GetBC25519Curve()
	assert.NoError(t, err)
	handler := Handler(BC25519)
	keyMaterial, err := handler.Generate()
	assert.NoError(t, err)

	assert.NotEmpty(t, keyMaterial.Nonce)
	assert.NotEmpty(t, keyMaterial.PrivateKey)
	assert.NotEmpty(t, keyMaterial.PublicKey)
	assert.NotEmpty(t, keyMaterial.X509PublicKey)

	// sharedSecret, err := utils.ComputeSharedSecret(keyMaterial.PrivateKey, keyMaterial.PublicKey)
	// assert.NoError(t, err)
	// assert.NotEmpty(t, sharedSecret)
}
