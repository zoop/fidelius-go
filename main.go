package main

import (
	"encoding/json"
	"fmt"

	"github.com/zoop/fidelius-go/decryption"
	"github.com/zoop/fidelius-go/encryption"
	"github.com/zoop/fidelius-go/keypairgen"
	"github.com/zoop/fidelius-go/utils"
)

/* -------------------------------------------------------------------------- */
/*                                    main                                    */
/* -------------------------------------------------------------------------- */
// Refer :- https://i.ibb.co/cNb7S4h/Encryption.png
func main() {
	BC25519, err := utils.GetBC25519Curve()
	if err != nil {
		fmt.Println("Error not able create curve")
		return
	}
	handler := keypairgen.Handler(BC25519)
	keyMaterial, err := handler.Generate()
	if err != nil {
		fmt.Println("Error generating key material:", err)
		return
	}

	jsonData, err := json.Marshal(keyMaterial)
	if err != nil {
		fmt.Println("Error marshaling key material to JSON:", err)
		return
	}

	fmt.Println(string(jsonData))
	fmt.Println("-------------------------------------------------------------------------")
	encryptionHandler := encryption.Handler(BC25519)

	senderNonce := keyMaterial.Nonce
	recieverNone := "MUFiMwG88uua0tf6Coh89DAYVDzglO3GV46jBBvw3KI="
	request := encryption.EncryptionRequest{
		StringToEncrypt:    "Hello, World!",
		SenderNonce:        senderNonce,
		RequesterNonce:     recieverNone,
		SenderPrivateKey:   keyMaterial.PrivateKey,
		RequesterPublicKey: "BDKIyX4Dl5mcY2igBWUyJDabZlVcwpBncbZW4sN4WzTEPcRb3VaNWfcjpGICwj6JOdXGPxkwEX6465MJG7X6IC8=",
	}
	response, err := encryptionHandler.Encrypt(request)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}
	fmt.Println("Encrypted Data:", response)

	fmt.Println("-------------------------------------------------------------------------")
	decryptionHandler := decryption.Handler(BC25519)
	req := decryption.DecryptionRequest{
		EncryptedData:       "pzMvVZNNVtJzqPkkxcCbBUWgDEBy/mBXIeT2dJWI16ZAQnnXUb9lI+S4k8XK6mgZSKKSRIHkcNvJpllnBg548wUgavBa0vCRRwdL6kY6Yw==",
		RequesterNonce:      "6uj1RdDUbcpI3lVMZvijkMC8Te20O4Bcyz0SyivX8Eg=",
		SenderNonce:         "lmXgblZwotx+DfBgKJF0lZXtAXgBEYr5khh79Zytr2Y=",
		RequesterPrivateKey: "DMxHPri8d7IT23KgLk281zZenMfVHSdeamq0RhwlIBk=",
		SenderPublicKey:     "BABVt+mpRLMXiQpIfEq6bj8hlXsdtXIxLsspmMgLNI1SR5mHgDVbjHO2A+U4QlMddGzqyEidzm1AkhtSxSO2Ahg=",
	}
	resp, err := decryptionHandler.Decrypt(req)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return
	}
	fmt.Println("Decrypted Data:", resp)
}
