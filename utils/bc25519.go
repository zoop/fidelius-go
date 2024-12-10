package utils

import "math/big"

func GetBC25519Curve() (*Curve, error) {
	// Define BC25519 curve parameters
	p, _ := new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	a, _ := new(big.Int).SetString("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144", 16)
	b, _ := new(big.Int).SetString("7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864", 16)
	q, _ := new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	gx, _ := new(big.Int).SetString("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a", 16)
	gy, _ := new(big.Int).SetString("20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9", 16)
	oid := []byte{0x01, 0x03, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x05, 0x01}
	curve, err := NewCurve("BC25519", p, a, b, q, gx, gy, oid)
	return curve, err
}
