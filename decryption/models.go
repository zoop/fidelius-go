package decryption

type DecryptionRequest struct {
	EncryptedData       string
	RequesterNonce      string
	SenderNonce         string
	RequesterPrivateKey string
	SenderPublicKey     string
}

type DecryptionResponse struct {
	DecryptedData string
}
