package keypairgen

type KeyMaterial struct {
	PrivateKey    string `json:"privateKey"`
	PublicKey     string `json:"publicKey"`
	X509PublicKey string `json:"x509PublicKey"`
	Nonce         string `json:"nonce"`
}
