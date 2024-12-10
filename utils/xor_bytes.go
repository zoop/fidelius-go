package utils

import "errors"

/* -------------------------------------------------------------------------- */
/*                                  XORBytes                                  */
/* -------------------------------------------------------------------------- */
// Performs XOR operation between two byte slices of the same length.
func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("nonces must have the same length")
	}
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}
