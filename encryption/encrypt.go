package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	"github.com/zoop/fidelius-go/utils"
)

/* -------------------------------------------------------------------------- */
/*                                   Encrypt                                  */
/* -------------------------------------------------------------------------- */
func (cc *encryptionHandler) Encrypt(req EncryptionRequest) (string, error) {
	// Decode base64 nonces
	senderNonce, err := base64.StdEncoding.DecodeString(req.SenderNonce)
	if err != nil {
		return "", err
	}
	requesterNonce, err := base64.StdEncoding.DecodeString(req.RequesterNonce)
	if err != nil {
		return "", err
	}

	// XOR nonces to generate IV and salt
	xorOfNonces, err := utils.XORBytes(senderNonce, requesterNonce)
	if err != nil {
		return "", err
	}

	iv := xorOfNonces[len(xorOfNonces)-12:] // Last 12 bytes for IV
	salt := xorOfNonces[:20]                // First 20 bytes for salt

	// Compute the shared secret
	sharedSecret, err := utils.ComputeSharedSecret(req.SenderPrivateKey, req.RequesterPublicKey, cc.Curve)
	if err != nil {
		return "", err
	}

	// Derive the AES encryption key using HKDF
	aesEncryptionKey, err := utils.Sha256HKDF(salt, sharedSecret, 32)
	if err != nil {
		return "", err
	}

	// Create AES cipher block
	block, err := aes.NewCipher(aesEncryptionKey)
	if err != nil {
		return "", err
	}

	// Use GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt the data
	plaintext := []byte(req.StringToEncrypt)
	ciphertext := aesGCM.Seal(nil, iv, plaintext, nil)

	// Return base64-encoded ciphertext (data + tag)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
