package commitment

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"golang.org/x/crypto/bn256"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

func KzgCommitment() {
	k, err := rand.Int(rand.Reader, bn256.Order) // bn256.Order is the group order
	if err != nil {
		panic(err)
	}
	fmt.Println("Random scalar k = ", k)

	//// 2) Multiply the base generator by k to get a random point on G1
	//G := new(bn256.G1).ScalarBaseMult(k)

	// 1. Generate an SRS (Structured Reference String) for KZG
	//    The size parameter indicates the maximum polynomial degree we want to support.
	//    For a small example, let's choose a small size (e.g., 8).

	srsSize := uint64(8)
	srs, err := kzg_bn254.NewSRS(srsSize, k)
	if err != nil {
		panic(err)
	}

	// 2. Build a polynomial f(X). We'll create a polynomial of degree 2, for example:
	//    f(X) = 5 + 2X + 3X^2 in the scalar field of BN254.
	//    We represent polynomials as a slice of bn254 field elements (lowest degree first).
	fCoeffs := make(polynomial.Polynomial, 3)
	fCoeffs[0].SetUint64(5) // constant term
	fCoeffs[1].SetUint64(2) // X^1 coefficient
	fCoeffs[2].SetUint64(3) // X^2 coefficient

	// 3. Commit to the polynomial using KZG
	commit, err := kzg_bn254.Commit(fCoeffs, srs.Pk)
	if err != nil {
		panic(err)
	}
	fmt.Println("KZG Commitment (G1 point):", commit)

	// 4. Suppose we want to prove the evaluation f(x) at x = 10 and then verify it.
	//    4a. Convert 10 to a field element
	var x fr.Element
	x.SetUint64(11)

	//    4b. Compute f(10) in the field
	fx := fCoeffs.Eval(&x)
	fmt.Println("f(11) =", fx)

	//    4c. Generate proof pi = Open(f, x)
	pi, err := kzg_bn254.Open(fCoeffs, x, srs.Pk)
	if err != nil {
		panic(err)
	}

	// 5. Verify the opening: check that f(10) = fx given the commitment
	if err := kzg_bn254.Verify(&commit, &pi, x, srs.Vk); err != nil {
		fmt.Println("Verification failed:", err)
	} else {
		fmt.Println("Verification succeeded!")
	}
}

func randUint64() (uint64, error) {
	b := make([]byte, bn254.ID.BaseField().Uint64())
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

func KzgCommitmentAndVerificationDemo() {

	// 1. Generate a random scalar for the SRS
	//    (You could also use rand.Reader directly, but let's keep it explicit.)
	k, err := rand.Int(rand.Reader, new(big.Int).SetUint64(1<<62)) // a random big.Int
	if err != nil {
		panic(err)
	}
	fmt.Println("Random scalar k for SRS =", k)

	// 2. Generate an SRS for polynomials up to degree 8.
	//    SRS = {Pk, Vk}, which are the Proving and Verifying keys.
	srsSize := uint64(8)
	srs, err := kzg_bn254.NewSRS(srsSize, k)
	if err != nil {
		panic(err)
	}

	// 3. Define a polynomial f(X) = 5 + 2X + 3X^2
	fCoeffs := make(polynomial.Polynomial, 3)
	fCoeffs[0].SetUint64(5) // constant
	fCoeffs[1].SetUint64(2) // X^1 coefficient
	fCoeffs[2].SetUint64(3) // X^2 coefficient

	// 4. Commit to polynomial f
	commit, err := kzg_bn254.Commit(fCoeffs, srs.Pk)
	if err != nil {
		panic(err)
	}
	fmt.Println("KZG Commitment (G1 element):", commit)

	// 5. Choose a point x = 11 for evaluation
	var x fr.Element
	x.SetUint64(11)

	// 6. Compute f(x) in the field
	fx := fCoeffs.Eval(&x)
	fmt.Println("f(11) =", fx)

	// 7. Generate a proof pi of correct evaluation
	pi, err := kzg_bn254.Open(fCoeffs, x, srs.Pk)
	if err != nil {
		panic(err)
	}

	// 8. Verify the proof -> Should SUCCEED
	err = kzg_bn254.Verify(&commit, &pi, x, srs.Vk)
	if err != nil {
		fmt.Println("Verification (correct) FAILED unexpectedly:", err)
	} else {
		fmt.Println("Verification (correct) SUCCEEDED as expected.")
	}

	// -------------------------------------------------------------------------
	// EXAMPLE OF FAILING VERIFICATION
	// -------------------------------------------------------------------------

	// Let's try verifying the same proof at a different evaluation point: x = 12
	var wrongX fr.Element
	wrongX.SetUint64(12)

	err = kzg_bn254.Verify(&commit, &pi, wrongX, srs.Vk)
	if err != nil {
		fmt.Println("Verification (wrong x) FAILED as expected:", err)
	} else {
		fmt.Println("Verification (wrong x) SUCCEEDED (which should NOT happen)!")
	}
}
