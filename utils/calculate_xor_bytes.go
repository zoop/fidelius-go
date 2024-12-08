package utils

import "errors"

/* -------------------------------------------------------------------------- */
/*                             CalculateXorOfBytes                            */
/* -------------------------------------------------------------------------- */
func CalculateXorOfBytes(byteArrayA, byteArrayB []byte) ([]byte, error) {
	if len(byteArrayA) != len(byteArrayB) {
		return nil, errors.New("inputs must have the same length for XOR operation")
	}

	xorOfBytes := make([]byte, len(byteArrayA))
	for i := range byteArrayA {
		xorOfBytes[i] = byteArrayA[i] ^ byteArrayB[i%len(byteArrayB)]
	}
	return xorOfBytes, nil
}
