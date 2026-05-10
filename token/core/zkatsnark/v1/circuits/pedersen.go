/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package circuits contains gnark circuit definitions for the zkatsnark token driver.
// It implements Pedersen commitments on Baby Jubjub (the twisted Edwards curve
// embedded in BN254) proved using Groth16 SNARKs.
package circuits

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// PedersenCommitment is a reusable circuit gadget that proves knowledge of
// a valid opening (TypeHash, Value, BlindingFactor) of a Pedersen commitment
// on Baby Jubjub.
//
// The commitment equation is:
//
//	C = TypeHash * K + Value * G + BlindingFactor * H
//
// where G is the Baby Jubjub base point (embedded as a constant from the curve
// parameters), H is the second independent generator for value hiding, and K is
// the third independent generator for token-type hiding. H and K are passed as
// public inputs from the driver's public parameters.
//
// This 3-generator structure matches the existing zkatdlog commitment scheme,
// which commits to (type, value, blinding_factor) using PedersenGenerators.
type PedersenCommitment struct {
	// CX and CY are the public commitment coordinates.
	CX frontend.Variable
	CY frontend.Variable

	// TypeHash is the secret scalar derived by hashing the token type string
	// to a field element (e.g. Fr.SetBytes(sha256("USD"))).
	TypeHash frontend.Variable

	// Value is the secret token value being committed to.
	Value frontend.Variable

	// BlindingFactor is the secret randomness that hides the value.
	BlindingFactor frontend.Variable

	// HX and HY are the coordinates of the second Pedersen generator H (for value).
	// These are public inputs set from the driver's public parameters.
	HX frontend.Variable
	HY frontend.Variable

	// KX and KY are the coordinates of the third Pedersen generator K (for type).
	// These are public inputs set from the driver's public parameters.
	KX frontend.Variable
	KY frontend.Variable
}

// verify enforces the Pedersen commitment equation inside the circuit:
//
//	C = TypeHash * K + Value * G + BlindingFactor * H
//
// It must be called from within a parent circuit's Define method.
func (c *PedersenCommitment) verify(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	// G is the Baby Jubjub base point, a circuit constant derived from the curve params.
	params := curve.Params()
	G := twistededwards.Point{X: params.Base[0], Y: params.Base[1]}

	// H is the second generator (for value), a public input from the driver's public parameters.
	H := twistededwards.Point{X: c.HX, Y: c.HY}

	// K is the third generator (for type), a public input from the driver's public parameters.
	K := twistededwards.Point{X: c.KX, Y: c.KY}

	// Compute TypeHash * K + Value * G + BlindingFactor * H and assert it equals the commitment.
	typeK := curve.ScalarMul(K, c.TypeHash)
	vG := curve.ScalarMul(G, c.Value)
	bfH := curve.ScalarMul(H, c.BlindingFactor)

	tmp := curve.Add(typeK, vG)
	computed := curve.Add(tmp, bfH)

	api.AssertIsEqual(computed.X, c.CX)
	api.AssertIsEqual(computed.Y, c.CY)

	return nil
}
