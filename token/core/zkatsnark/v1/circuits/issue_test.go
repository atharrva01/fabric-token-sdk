/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package circuits_test

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	babyjubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger-labs/fabric-token-sdk/token/core/zkatsnark/v1/circuits"
)

// setupGenerators returns the Baby Jubjub base point G and two independent
// generators H = 2*G (for value) and K = 3*G (for type).
//
// NOTE: H = 2*G and K = 3*G are provisional choices for the PoC. The final driver
// will derive H and K via hash-to-curve to ensure they are "nothing-up-my-sleeve"
// generators with no known discrete-log relationship to G.
func setupGenerators() (G, H, K babyjubjub.PointAffine) {
	edParams := babyjubjub.GetEdwardsCurve()
	G = edParams.Base
	H.Double(&G)
	K.Add(&H, &G) // K = 3*G
	return
}

// typeHashScalar hashes a token type string to a BN254 scalar field element.
// This mirrors the Fr.SetBytes(sha256(tokenType)) derivation that the driver will
// perform outside the circuit before building the prover witness.
func typeHashScalar(tokenType string) (big.Int, fr.Element) {
	digest := sha256.Sum256([]byte(tokenType))
	var elem fr.Element
	elem.SetBytes(digest[:])
	var b big.Int
	elem.BigInt(&b)
	return b, elem
}

// computeCommitment computes TypeHash*K + Value*G + BlindingFactor*H on Baby Jubjub.
func computeCommitment(G, H, K *babyjubjub.PointAffine, typeHashBig *big.Int, value, bf uint64) babyjubjub.PointAffine {
	var v, b fr.Element
	v.SetUint64(value)
	b.SetUint64(bf)

	var vBig, bBig big.Int
	v.BigInt(&vBig)
	b.BigInt(&bBig)

	var typeK, vG, bH, com babyjubjub.PointAffine
	typeK.ScalarMultiplication(K, typeHashBig)
	vG.ScalarMultiplication(G, &vBig)
	bH.ScalarMultiplication(H, &bBig)

	com.Add(&typeK, &vG)
	com.Add(&com, &bH)
	return com
}

// issuerKeyPair derives a Baby Jubjub key pair from a secret scalar.
func issuerKeyPair(secret uint64) (privBig big.Int, pub babyjubjub.PointAffine) {
	edParams := babyjubjub.GetEdwardsCurve()
	G := edParams.Base

	var priv fr.Element
	priv.SetUint64(secret)
	priv.BigInt(&privBig)
	pub.ScalarMultiplication(&G, &privBig)
	return
}

// TestIssueCircuit_ProveAndVerify is the end-to-end happy-path test.
// It compiles the circuit, runs a trusted setup, generates a Groth16 proof
// for a valid issuance, and verifies it.
func TestIssueCircuit_ProveAndVerify(t *testing.T) {
	G, H, K := setupGenerators()
	typeHashBig, _ := typeHashScalar("USD")

	privBig, pubKey := issuerKeyPair(12345)

	value := uint64(100)
	bf := uint64(42)
	commitment := computeCommitment(&G, &H, &K, &typeHashBig, value, bf)

	assignment := &circuits.IssueCircuit{
		IssuerPubKeyX:  pubKey.X.BigInt(new(big.Int)),
		IssuerPubKeyY:  pubKey.Y.BigInt(new(big.Int)),
		CommitmentX:    commitment.X.BigInt(new(big.Int)),
		CommitmentY:    commitment.Y.BigInt(new(big.Int)),
		HX:             H.X.BigInt(new(big.Int)),
		HY:             H.Y.BigInt(new(big.Int)),
		KX:             K.X.BigInt(new(big.Int)),
		KY:             K.Y.BigInt(new(big.Int)),
		MaxValue:       new(big.Int).SetUint64(1_000_000),
		IssuerPrivKey:  privBig,
		TypeHash:       &typeHashBig,
		Value:          new(big.Int).SetUint64(value),
		BlindingFactor: new(big.Int).SetUint64(bf),
	}

	// Compile the circuit into an R1CS.
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuits.IssueCircuit{})
	require.NoError(t, err)
	t.Logf("IssueCircuit compiled: %d constraints", ccs.GetNbConstraints())

	// Trusted setup: derive proving and verification keys.
	pk, vk, err := groth16.Setup(ccs)
	require.NoError(t, err)

	// Build the full witness and generate the proof.
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	proof, err := groth16.Prove(ccs, pk, witness)
	require.NoError(t, err)

	// Verify: extract only the public part of the witness.
	pubWitness, err := witness.Public()
	require.NoError(t, err)

	err = groth16.Verify(proof, vk, pubWitness)
	require.NoError(t, err)

	t.Log("proof verified: issuance of 100 USD tokens accepted")
}

// TestIssueCircuit_ValueExceedsMax checks that a value above MaxValue is rejected.
func TestIssueCircuit_ValueExceedsMax(t *testing.T) {
	G, H, K := setupGenerators()
	typeHashBig, _ := typeHashScalar("USD")

	privBig, pubKey := issuerKeyPair(999)

	// Issue a value higher than MaxValue.
	value := uint64(2_000_000)
	bf := uint64(7)
	commitment := computeCommitment(&G, &H, &K, &typeHashBig, value, bf)

	assignment := &circuits.IssueCircuit{
		IssuerPubKeyX:  pubKey.X.BigInt(new(big.Int)),
		IssuerPubKeyY:  pubKey.Y.BigInt(new(big.Int)),
		CommitmentX:    commitment.X.BigInt(new(big.Int)),
		CommitmentY:    commitment.Y.BigInt(new(big.Int)),
		HX:             H.X.BigInt(new(big.Int)),
		HY:             H.Y.BigInt(new(big.Int)),
		KX:             K.X.BigInt(new(big.Int)),
		KY:             K.Y.BigInt(new(big.Int)),
		MaxValue:       new(big.Int).SetUint64(1_000_000),
		IssuerPrivKey:  privBig,
		TypeHash:       &typeHashBig,
		Value:          new(big.Int).SetUint64(value),
		BlindingFactor: new(big.Int).SetUint64(bf),
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuits.IssueCircuit{})
	require.NoError(t, err)

	pk, _, err := groth16.Setup(ccs)
	require.NoError(t, err)

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	// Proof generation must fail: value > MaxValue violates the range constraint.
	_, err = groth16.Prove(ccs, pk, witness)
	require.Error(t, err, "expected proof to fail when value exceeds MaxValue")
	t.Logf("correctly rejected: value %d > MaxValue %d", value, uint64(1_000_000))
}

// TestIssueCircuit_WrongPrivKey checks that an incorrect issuer key is rejected.
func TestIssueCircuit_WrongPrivKey(t *testing.T) {
	G, H, K := setupGenerators()
	typeHashBig, _ := typeHashScalar("USD")

	_, pubKey := issuerKeyPair(12345)
	wrongPriv, _ := issuerKeyPair(99999) // different key

	value := uint64(50)
	bf := uint64(11)
	commitment := computeCommitment(&G, &H, &K, &typeHashBig, value, bf)

	assignment := &circuits.IssueCircuit{
		IssuerPubKeyX:  pubKey.X.BigInt(new(big.Int)),   // real pubkey
		IssuerPubKeyY:  pubKey.Y.BigInt(new(big.Int)),
		CommitmentX:    commitment.X.BigInt(new(big.Int)),
		CommitmentY:    commitment.Y.BigInt(new(big.Int)),
		HX:             H.X.BigInt(new(big.Int)),
		HY:             H.Y.BigInt(new(big.Int)),
		KX:             K.X.BigInt(new(big.Int)),
		KY:             K.Y.BigInt(new(big.Int)),
		MaxValue:       new(big.Int).SetUint64(1_000_000),
		IssuerPrivKey:  wrongPriv,                        // wrong private key
		TypeHash:       &typeHashBig,
		Value:          new(big.Int).SetUint64(value),
		BlindingFactor: new(big.Int).SetUint64(bf),
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuits.IssueCircuit{})
	require.NoError(t, err)

	pk, _, err := groth16.Setup(ccs)
	require.NoError(t, err)

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	// Proof generation must fail: wrong privKey * G != pubKey.
	_, err = groth16.Prove(ccs, pk, witness)
	require.Error(t, err, "expected proof to fail for mismatched issuer key")
	t.Log("correctly rejected: wrong issuer private key")
}

// TestIssueCircuit_WrongTypeHash checks that a mismatched token type is rejected.
// The commitment encodes type "USD" but the witness claims type "EUR".
func TestIssueCircuit_WrongTypeHash(t *testing.T) {
	G, H, K := setupGenerators()
	usdHashBig, _ := typeHashScalar("USD")
	eurHashBig, _ := typeHashScalar("EUR")

	privBig, pubKey := issuerKeyPair(12345)

	value := uint64(100)
	bf := uint64(42)
	// Commitment encodes USD type.
	commitment := computeCommitment(&G, &H, &K, &usdHashBig, value, bf)

	assignment := &circuits.IssueCircuit{
		IssuerPubKeyX:  pubKey.X.BigInt(new(big.Int)),
		IssuerPubKeyY:  pubKey.Y.BigInt(new(big.Int)),
		CommitmentX:    commitment.X.BigInt(new(big.Int)),
		CommitmentY:    commitment.Y.BigInt(new(big.Int)),
		HX:             H.X.BigInt(new(big.Int)),
		HY:             H.Y.BigInt(new(big.Int)),
		KX:             K.X.BigInt(new(big.Int)),
		KY:             K.Y.BigInt(new(big.Int)),
		MaxValue:       new(big.Int).SetUint64(1_000_000),
		IssuerPrivKey:  privBig,
		TypeHash:       &eurHashBig, // wrong: EUR hash vs USD commitment
		Value:          new(big.Int).SetUint64(value),
		BlindingFactor: new(big.Int).SetUint64(bf),
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuits.IssueCircuit{})
	require.NoError(t, err)

	pk, _, err := groth16.Setup(ccs)
	require.NoError(t, err)

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)

	// Proof generation must fail: wrong type hash does not open the commitment.
	_, err = groth16.Prove(ccs, pk, witness)
	require.Error(t, err, "expected proof to fail for mismatched token type")
	t.Log("correctly rejected: wrong token type hash")
}
