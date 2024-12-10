package utils

import (
	"fmt"
	"math/big"
)

// Point represents a point on an elliptic curve.
type Point struct {
	X     *big.Int
	Y     *big.Int
	Curve *Curve
}

// IdentityPoint represents the point at infinity.
var IdentityPoint = &Point{X: big.NewInt(0), Y: big.NewInt(0), Curve: nil}

// CurveMismatchError is raised when trying to add points from different curves.
type CurveMismatchError struct {
	Curve1, Curve2 *Curve
}

// Error method for CurveMismatchError.
func (e *CurveMismatchError) Error() string {
	return fmt.Sprintf("Tried to add points on two different curves <%s> & <%s>", e.Curve1.Name, e.Curve2.Name)
}

// NewPoint creates a new elliptic curve point.
func NewPoint(x, y *big.Int, curve *Curve) (*Point, error) {
	// Ensure the point lies on the curve
	if !curve.IsPointOnCurve(x, y) {
		return nil, fmt.Errorf("coordinates are not on curve <%s>\n\tx=%x\ny=%x", curve.Name, x, y)
	}
	return &Point{X: x, Y: y, Curve: curve}, nil
}

// Add adds two points on the same elliptic curve.
func (p *Point) Add(q *Point) (*Point, error) {
	// Point at infinity cases
	if p == IdentityPoint {
		return q, nil
	}
	if q == IdentityPoint {
		return p, nil
	}
	if p.X.Cmp(q.X) == 0 && p.Y.Cmp(new(big.Int).Neg(q.Y).Mod(new(big.Int).Neg(q.Y), p.Curve.P)) == 0 {
		return IdentityPoint, nil
	}

	// Compute lambda (slope) for point addition
	var lambda *big.Int
	if p.X.Cmp(q.X) == 0 {
		// Tangent line case
		twoY := new(big.Int).Mul(big.NewInt(2), p.Y)
		twoY.ModInverse(twoY, p.Curve.P)
		num := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(p.X, p.X)) // 3 * x^2
		num.Add(num, p.Curve.A)                                            // 3 * x^2 + a
		lambda = new(big.Int).Mul(num, twoY)
	} else {
		// Line connecting p and q
		num := new(big.Int).Sub(q.Y, p.Y)
		denom := new(big.Int).Sub(q.X, p.X)
		denom.ModInverse(denom, p.Curve.P)
		lambda = new(big.Int).Mul(num, denom)
	}

	lambda.Mod(lambda, p.Curve.P)

	// Calculate the new x and y coordinates
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, p.X)
	x3.Sub(x3, q.X)
	x3.Mod(x3, p.Curve.P)

	y3 := new(big.Int).Sub(p.X, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, p.Y)
	y3.Mod(y3, p.Curve.P)

	return NewPoint(x3, y3, p.Curve)
}

// Negate returns the negation of a point (reflection over the x-axis).
func (p *Point) Negate() *Point {
	return &Point{
		X:     p.X,
		Y:     new(big.Int).Neg(p.Y).Mod(new(big.Int).Neg(p.Y), p.Curve.P),
		Curve: p.Curve,
	}
}

// ScalarMul performs scalar multiplication on a point.
func (p *Point) ScalarMul(scalar *big.Int) *Point {
	result := IdentityPoint
	current := p
	scalarBits := scalar.Text(2) // Binary representation of scalar

	for _, bit := range scalarBits {
		result, _ = result.Add(result)
		if bit == '1' {
			result, _ = result.Add(current)
		}
	}

	return result
}
