package encryption

type EncryptionRequest struct {
	SenderNonce           string
	RequesterNonce        string
	SenderPrivateKey      string
	RequesterPublicKey    string
	StringToEncrypt       string
	StringToEncryptBase64 *string
}
