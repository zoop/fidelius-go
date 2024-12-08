package decryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fidelius-go/utils"
)

/* -------------------------------------------------------------------------- */
/*                                   Decrypt                                  */
/* -------------------------------------------------------------------------- */
func (d *decryptionHandler) Decrypt(req DecryptionRequest) (DecryptionResponse, error) {
	// Decode base64 nonces
	senderNonce, err := utils.DecodeBase64(req.SenderNonce)
	if err != nil {
		return DecryptionResponse{}, err
	}
	requesterNonce, err := utils.DecodeBase64(req.RequesterNonce)
	if err != nil {
		return DecryptionResponse{}, err
	}

	// Compute XOR of nonces
	xorOfNonces, err := utils.CalculateXorOfBytes(senderNonce, requesterNonce)
	if err != nil {
		return DecryptionResponse{}, err
	}

	// Extract IV and salt
	iv := xorOfNonces[len(xorOfNonces)-12:]
	salt := xorOfNonces[:20]

	// Decode encrypted data
	encryptedBytes, err := utils.DecodeBase64(req.EncryptedData)
	if err != nil {
		return DecryptionResponse{}, err
	}

	// Compute shared secret
	sharedSecret, err := utils.ComputeSharedSecret(req.RequesterPrivateKey, req.SenderPublicKey)
	if err != nil {
		return DecryptionResponse{}, err
	}

	// Derive AES encryption key using HKDF
	aesEncryptionKey := utils.DeriveKeyFromHKDF(salt, sharedSecret, 32)

	// Decrypt the data
	decryptedData, err := d.aesGCMDecrypt(aesEncryptionKey, iv, encryptedBytes)
	if err != nil {
		return DecryptionResponse{}, err
	}

	return DecryptionResponse{DecryptedData: string(decryptedData)}, nil
}

/* -------------------------------------------------------------------------- */
/*                                AESGCMDecrypt                               */
/* -------------------------------------------------------------------------- */
func (d *decryptionHandler) aesGCMDecrypt(key, iv, encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesGCM.Open(nil, iv, encryptedData, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
