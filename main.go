package main

import (
	"encoding/json"
	"fmt"

	"github.com/zoop/fidelius-go/decryption"
	"github.com/zoop/fidelius-go/encryption"
	"github.com/zoop/fidelius-go/keypairgen"
	"github.com/zoop/fidelius-go/utils"
)

// https://i.ibb.co/cNb7S4h/Encryption.png
func main() {
	handler := keypairgen.Handler()
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
	encryptionHandler := encryption.Handler()

	senderNonce := utils.GenerateRandomNonce(32)
	recieverNone := utils.GenerateRandomNonce(32)
	request := &encryption.EncryptionRequest{
		StringToEncrypt:    "Hello, World!",
		SenderNonce:        senderNonce,
		RequesterNonce:     recieverNone,
		SenderPrivateKey:   keyMaterial.PrivateKey,
		RequesterPublicKey: keyMaterial.PublicKey,
	}
	response, err := encryptionHandler.Encrypt(request)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}
	fmt.Println("Encrypted Data:", response.EncryptedData)

	fmt.Println("-------------------------------------------------------------------------")
	decryptionHandler := decryption.Handler()
	req := decryption.DecryptionRequest{
		EncryptedData:       response.EncryptedData,
		RequesterNonce:      senderNonce,
		SenderNonce:         recieverNone,
		RequesterPrivateKey: keyMaterial.PrivateKey,
		SenderPublicKey:     keyMaterial.PublicKey,
	}
	resp, err := decryptionHandler.Decrypt(req)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return
	}
	fmt.Println("Decrypted Data:", resp.DecryptedData)
}
