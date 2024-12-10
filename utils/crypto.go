package utils

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// GeneratePrivateKey generates a private key for the given curve.
// The private key is a random integer in the range [1, q-1].
func GeneratePrivateKey(curve *Curve) (*big.Int, error) {
	if curve == nil {
		return nil, errors.New("curve cannot be nil")
	}
	// Generate a random private key in the range [1, q-1]
	privateKey, err := rand.Int(rand.Reader, new(big.Int).Sub(curve.Q, big.NewInt(1)))
	if err != nil {
		return nil, err
	}
	privateKey.Add(privateKey, big.NewInt(1)) // Ensure privateKey is >= 1
	return privateKey, nil
}

// GeneratePublicKey generates a public key from the given private key and curve.
// The public key is the result of scalar multiplication of the private key with the base point (G).
func GeneratePublicKey(curve *Curve, privateKey *big.Int) (*big.Int, *big.Int, error) {
	if curve == nil {
		return nil, nil, errors.New("curve cannot be nil")
	}
	if privateKey == nil || privateKey.Cmp(big.NewInt(1)) < 0 || privateKey.Cmp(curve.Q) >= 0 {
		return nil, nil, errors.New("invalid private key")
	}

	// Perform scalar multiplication: P = privateKey * G
	publicKeyX, publicKeyY := scalarMult(curve.Gx, curve.Gy, privateKey, curve)
	return publicKeyX, publicKeyY, nil
}

// scalarMult performs scalar multiplication (k * P) on the curve using double-and-add method.
func scalarMult(x, y, k *big.Int, curve *Curve) (*big.Int, *big.Int) {
	resultX, resultY := big.NewInt(0), big.NewInt(0) // Initialize to the point at infinity
	addX, addY := new(big.Int).Set(x), new(big.Int).Set(y)

	for i := k.BitLen() - 1; i >= 0; i-- {
		// Double the current point
		resultX, resultY = pointDouble(resultX, resultY, curve)

		// Add the base point if the current bit of k is set
		if k.Bit(i) == 1 {
			resultX, resultY = pointAdd(resultX, resultY, addX, addY, curve)
		}
	}

	return resultX, resultY
}

// pointAdd performs point addition (P1 + P2) on the curve.
func pointAdd(x1, y1, x2, y2 *big.Int, curve *Curve) (*big.Int, *big.Int) {
	// Handle the point at infinity
	if x1.Cmp(big.NewInt(0)) == 0 && y1.Cmp(big.NewInt(0)) == 0 {
		return x2, y2
	}
	if x2.Cmp(big.NewInt(0)) == 0 && y2.Cmp(big.NewInt(0)) == 0 {
		return x1, y1
	}

	// Calculate the slope
	lambda := new(big.Int)
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		// Slope for point doubling: λ = (3x1^2 + a) / (2y1) mod p
		numerator := new(big.Int).Add(new(big.Int).Mul(big.NewInt(3), new(big.Int).Exp(x1, big.NewInt(2), curve.P)), curve.A)
		denominator := new(big.Int).Mul(big.NewInt(2), y1)
		lambda.ModInverse(denominator, curve.P) // λ = numerator / denominator mod p
		lambda.Mul(lambda, numerator).Mod(lambda, curve.P)
	} else {
		// Slope for point addition: λ = (y2 - y1) / (x2 - x1) mod p
		numerator := new(big.Int).Sub(y2, y1)
		denominator := new(big.Int).Sub(x2, x1)
		lambda.ModInverse(denominator, curve.P) // λ = numerator / denominator mod p
		lambda.Mul(lambda, numerator).Mod(lambda, curve.P)
	}

	// Calculate the new point coordinates
	x3 := new(big.Int).Sub(new(big.Int).Exp(lambda, big.NewInt(2), curve.P), new(big.Int).Add(x1, x2))
	x3.Mod(x3, curve.P)
	y3 := new(big.Int).Sub(new(big.Int).Mul(lambda, new(big.Int).Sub(x1, x3)), y1)
	y3.Mod(y3, curve.P)

	return x3, y3
}

// pointDouble performs point doubling (2 * P) on the curve.
func pointDouble(x, y *big.Int, curve *Curve) (*big.Int, *big.Int) {
	return pointAdd(x, y, x, y, curve)
}
