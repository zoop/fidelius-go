package utils

import (
	"encoding/base64"
)

/* -------------------------------------------------------------------------- */
/*                                DecodeBase64                                */
/* -------------------------------------------------------------------------- */
func DecodeBase64(data string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	return decoded, err
}

/* -------------------------------------------------------------------------- */
/*                                EncodeBase64                                */
/* -------------------------------------------------------------------------- */
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
