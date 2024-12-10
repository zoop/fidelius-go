package utils

import (
	"errors"
	"math/big"
)

// Curve represents an elliptic curve defined by the equation y^2 = x^3 + ax + b (mod p).
type Curve struct {
	Name string   // The name of the curve
	P    *big.Int // The prime p in the curve equation
	A    *big.Int // The coefficient a in the curve equation
	B    *big.Int // The coefficient b in the curve equation
	Q    *big.Int // The order of the base point
	Gx   *big.Int // The x-coordinate of the base point
	Gy   *big.Int // The y-coordinate of the base point
	OID  []byte   // The object identifier of the curve
}

// oidLookup is a map to look up curves by their OID.
var oidLookup = map[string]*Curve{}

// NewCurve initializes a new Curve instance.
func NewCurve(name string, p, a, b, q, gx, gy *big.Int, oid []byte) (*Curve, error) {
	curve := &Curve{
		Name: name,
		P:    p,
		A:    a,
		B:    b,
		Q:    q,
		Gx:   gx,
		Gy:   gy,
		OID:  oid,
	}
	if len(oid) > 0 {
		oidLookup[string(oid)] = curve
	}
	return curve, nil
}

// GetCurveByOID retrieves a curve by its object identifier.
func GetCurveByOID(oid []byte) (*Curve, error) {
	curve, exists := oidLookup[string(oid)]
	if !exists {
		return nil, errors.New("curve not found")
	}
	return curve, nil
}

// IsPointOnCurve checks if a point (x, y) lies on the curve.
func (c *Curve) IsPointOnCurve(x, y *big.Int) bool {
	left := new(big.Int).Exp(y, big.NewInt(2), c.P)  // y^2 mod p
	right := new(big.Int).Exp(x, big.NewInt(3), c.P) // x^3 mod p
	right.Add(right, new(big.Int).Mul(c.A, x))       // x^3 + ax
	right.Add(right, c.B)                            // x^3 + ax + b
	right.Mod(right, c.P)                            // (x^3 + ax + b) mod p

	return left.Cmp(right) == 0
}

// Evaluate evaluates the curve polynomial at a given x.
func (c *Curve) Evaluate(x *big.Int) *big.Int {
	result := new(big.Int).Exp(x, big.NewInt(3), c.P) // x^3 mod p
	result.Add(result, new(big.Int).Mul(c.A, x))      // x^3 + ax
	result.Add(result, c.B)                           // x^3 + ax + b
	result.Mod(result, c.P)                           // (x^3 + ax + b) mod p
	return result
}

// BasePoint returns the base point (Gx, Gy) of the curve.
func (c *Curve) BasePoint() (*big.Int, *big.Int) {
	return c.Gx, c.Gy
}
