package decryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	"github.com/pkg/errors"
	"github.com/zoop/fidelius-go/utils"
)

/* -------------------------------------------------------------------------- */
/*                                   Decrypt                                  */
/* -------------------------------------------------------------------------- */

func (cc *decryptionHandler) Decrypt(req DecryptionRequest) (string, error) {
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
	sharedSecret, err := utils.ComputeSharedSecret(req.RequesterPrivateKey, req.SenderPublicKey, cc.Curve)
	if err != nil {
		return "", errors.Wrap(err, "[Decrypt][utils.ComputeSharedSecret]")
	}

	// Derive the AES encryption key using HKDF
	aesEncryptionKey, err := utils.Sha256HKDF(salt, sharedSecret, 32)
	if err != nil {
		return "", err
	}

	// Decode base64 encrypted data and split data + tag
	encryptedDataWithTag, err := base64.StdEncoding.DecodeString(req.EncryptedData)
	if err != nil {
		return "", err
	}
	if len(encryptedDataWithTag) < 16 {
		return "", errors.New("encrypted data too short")
	}

	// Create AES cipher block
	block, err := aes.NewCipher(aesEncryptionKey)
	if err != nil {
		return "", errors.Wrap(err, "[Decrypt][aes.NewCipher]")
	}

	// Use GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Decrypt the data
	plaintext, err := aesGCM.Open(nil, iv, encryptedDataWithTag, nil)
	if err != nil {
		return "", errors.Wrap(err, "[Decrypt][aesGCM.Open]")
	}

	// Return the decrypted string
	return string(plaintext), nil
}
