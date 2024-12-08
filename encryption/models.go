package encryption

type EncryptionRequest struct {
	StringToEncrypt    string
	SenderNonce        string
	RequesterNonce     string
	SenderPrivateKey   string
	RequesterPublicKey string
}

type EncryptionResponse struct {
	EncryptedData string
}
