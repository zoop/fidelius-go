package decryption

type DecryptionRequest struct {
	SenderNonce         string
	RequesterNonce      string
	RequesterPrivateKey string
	SenderPublicKey     string
	EncryptedData       string
}
