package keypairgen

import (
	"testing"

	"github.com/zoop/fidelius-go/utils"

	"github.com/stretchr/testify/assert"
)

/* -------------------------------------------------------------------------- */
/*                           Tests for GenerateTest                           */
/* -------------------------------------------------------------------------- */
func TestGenerateTest(t *testing.T) {
	handler := Handler()
	keyMaterial, err := handler.Generate()
	assert.NoError(t, err)

	assert.NotEmpty(t, keyMaterial.Nonce)
	assert.NotEmpty(t, keyMaterial.PrivateKey)
	assert.NotEmpty(t, keyMaterial.PublicKey)
	assert.NotEmpty(t, keyMaterial.X509PublicKey)

	sharedSecret, err := utils.ComputeSharedSecret(keyMaterial.PrivateKey, keyMaterial.PublicKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, sharedSecret)
}
