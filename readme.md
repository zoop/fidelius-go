# ZOOP FIDELIUS GO
github.com/zoop/fidelius-go is a Go library designed to simplify encryption and decryption processes in secure data exchange workflows between HIU (Health Information User), HCDM (Health Claims Data Manager), and HIP (Health Information Provider). It adheres to secure cryptographic standards and implements all the steps outlined in the data flow.

## Features
- Encryption: Generates secure keys, salts, and initialization vectors (IV) for encrypting sensitive data.
- Decryption: Decrypts the data using the corresponding keys and salts.
- Key Generation: Implements Diffie-Hellman key exchange (DHPK/DHSK) for shared key generation.
- Salt & IV Derivation: Uses XOR-based operations to derive salts and IV.
- HKDF AES Keying: Derives AES keys using HKDF for additional security.

## Installation

```
go get github.com/zoop/github.com/zoop/fidelius-go
```

## Usage
### Key Pair Generation
```
import (
	"github.com/zoop/fidelius-go/keypairgen"
	"github.com/zoop/fidelius-go/utils"
    "fmt"
)

func main() {
    BC25519, _ := utils.GetBC25519Curve()
    keyMaterial := keypairgen.Handler(BC25519)
    fmt.Println("Nonce", keyMaterial.Nonce)
	fmt.Println("PrivateKey", keyMaterial.PrivateKey)
	fmt.Println("PublicKey", keyMaterial.PublicKey)
	fmt.Println("X509PublicKey", keyMaterial.X509PublicKey)
}
```

### Encryption
```
import (
	"github.com/zoop/fidelius-go/encryption"
	"github.com/zoop/fidelius-go/utils"
    "fmt"
)

func main() {
    BC25519, _ := utils.GetBC25519Curve()
    encryptionHandler := encryption.Handler(BC25519)
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
    fmt.Println("Encrypted Data:", response)
}
```

### Decryption
```
import (
	"github.com/zoop/fidelius-go/decryption"
    "fmt"
)

func main() {
    BC25519, _ := utils.GetBC25519Curve()
    decryptionHandler := decryption.Handler(BC25519)
	req := decryption.DecryptionRequest{
		EncryptedData:       encryptedData,
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
	fmt.Println("Decrypted Data:", resp)
}
```

## Data Flow Overview
The library facilitates the encryption and decryption processes between HIP, HCDM, and HIU as follows:

### Encryption Steps:
- Verify Input Data
- Key and Random Value Generation:
- Generate DHPK(P) (Diffie-Hellman Public Key for HIP).
- Generate DHSK(P) (Diffie-Hellman Shared Key for HIP).
- Generate Rand(P) (Random Value for HIP).
- Shared Key Calculation:
    - Generate the shared key using DHSK(P) and DHPK(U) (Diffie-Hellman public key of the user).
- Salt and IV Generation:
    - Derive SALT and IV by XORing Rand(U) and Rand(P).

- Encryption:
    - Use HKDF to derive an AES key from the shared key and salt.
    - Encrypt the data using the AES key and the derived IV.
    - Send the encrypted data and DHPK(P) & Rand(P) to HIU.

### Decryption Steps
- Retrieve Keys and Random Values:
- Fetch DHSK(U) and Rand(U) from the database for the given data-flow request.
- Shared Key Calculation:
    - Generate the shared key using DHSK(U) and DHPK(P) (Diffie-Hellman public key of HIP).
- Salt and IV Generation:
    - Derive SALT and IV by XORing Rand(U) and Rand(P).
- Key Derivation:
    - Use HKDF to derive an AES key from the shared key and salt.
- Decryption:
- Decrypt the received data using the derived AES key and IV.