package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

/* -------------------------------------------------------------------------- */
/*                          EncodePrivateKeyToBase64                          */
/* -------------------------------------------------------------------------- */
// encodes a private key to base64 format.
func EncodePrivateKeyToBase64(key *big.Int) string {
	return base64.StdEncoding.EncodeToString(key.Bytes())
}

/* -------------------------------------------------------------------------- */
/*                           EncodePublicKeyToBase64                          */
/* -------------------------------------------------------------------------- */
// encodes a public key to base64 format in uncompressed form.
func EncodePublicKeyToBase64(x, y *big.Int) string {
	var buf bytes.Buffer
	buf.WriteByte(0x04) // Uncompressed point indicator
	buf.Write(x.Bytes())
	buf.Write(y.Bytes())
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

/* -------------------------------------------------------------------------- */
/*                         EncodeX509PublicKeyToBase64                        */
/* -------------------------------------------------------------------------- */
// encodes a public key to X.509 base64 format.
func EncodeX509PublicKeyToBase64(x, y *big.Int) (string, error) {
	// Prefix from Bouncy Castle X.509 public key encoding
	fixedPrefixB64 := "MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCANCAAQ="
	fixedPrefix, err := base64.StdEncoding.DecodeString(fixedPrefixB64)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	buf.Write(fixedPrefix)
	buf.Write(x.Bytes())
	buf.Write(y.Bytes())

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

/* -------------------------------------------------------------------------- */
/*                             GenerateBase64Nonce                            */
/* -------------------------------------------------------------------------- */
// generates a random nonce in base64 format.
func GenerateBase64Nonce() string {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(nonce)
}
