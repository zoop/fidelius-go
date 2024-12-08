package encryption

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/zoop/fidelius-go/utils"
)

/* -------------------------------------------------------------------------- */
/*                                   Encrypt                                  */
/* -------------------------------------------------------------------------- */
func (ec *encryptionHandler) Encrypt(request *EncryptionRequest) (*EncryptionResponse, error) {
	var encryptionResponse *EncryptionResponse
	senderNonce, err := utils.DecodeBase64(request.SenderNonce)
	if err != nil {
		return encryptionResponse, err
	}
	requesterNonce, err := utils.DecodeBase64(request.RequesterNonce)
	if err != nil {
		return encryptionResponse, err
	}
	xorOfNonces, err := utils.CalculateXorOfBytes(
		senderNonce,
		requesterNonce,
	)
	if err != nil {
		return nil, err
	}
	iv := xorOfNonces[len(xorOfNonces)-12:]
	salt := xorOfNonces[:20]
	encryptedData, err := ec.process(
		iv,
		salt,
		request.SenderPrivateKey,
		request.RequesterPublicKey,
		request.StringToEncrypt,
	)
	if err != nil {
		return nil, err
	}
	encryptionResponse = &EncryptionResponse{
		EncryptedData: encryptedData,
	}
	return encryptionResponse, nil
}

/* -------------------------------------------------------------------------- */
/*                                   Process                                  */
/* -------------------------------------------------------------------------- */
func (ec *encryptionHandler) process(
	iv []byte,
	salt []byte,
	senderPrivateKey string,
	requesterPublicKey string,
	stringToEncrypt string,
) (string, error) {
	sharedSecret, err := utils.ComputeSharedSecret(senderPrivateKey, requesterPublicKey)
	if err != nil {
		return "", err
	}
	aesEncryptionKey := utils.DeriveKey(salt, sharedSecret, 32)

	plaintext := []byte(stringToEncrypt)
	block, err := aes.NewCipher(aesEncryptionKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nil, iv, plaintext, nil)
	return utils.EncodeBase64(ciphertext), nil
}
