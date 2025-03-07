package commitment

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"golang.org/x/crypto/bn256"
)

// -----------------------------------------------------------------------------
//
//	Example: Single Pedersen Commitment/Proof
//
// -----------------------------------------------------------------------------
func ExampleSinglePedersen() {
	fmt.Println("---- [Single Pedersen Commitment/Proof Example] ----")

	// 1. Create a single "basis" for commitments, allowing 2 field elements per commitment.
	nbValues := 2
	basis := make([]bn254.G1Affine, nbValues)
	for i := 0; i < nbValues; i++ {
		// Important: use bn254.RandomG1Affine so each basis element is in the correct subgroup.
		_, _, g1aff, _ := bn254.Generators()

		basis[i] = g1aff
	}
	bases := [][]bn254.G1Affine{basis} // For a single set of bases

	// 2. Setup => produces pk[0] + a single vk
	pk, vk, err := pedersen.Setup(bases)
	if err != nil {
		panic(err)
	}

	// 3. Prepare two field elements to commit
	values := []fr.Element{fr.NewElement(123), fr.NewElement(456)}

	// 4. Commit
	commitment, err := pk[0].Commit(values)
	if err != nil {
		panic(err)
	}
	fmt.Println("Commitment G1:", commitment)

	// 5. Prove knowledge of these values
	proof, err := pk[0].ProveKnowledge(values)
	if err != nil {
		panic(err)
	}

	// 6. Verify
	if err := vk.Verify(commitment, proof); err != nil {
		fmt.Println("Single Pedersen verify: FAILED ->", err)
	} else {
		fmt.Println("Single Pedersen verify: SUCCEEDED")
	}

	// 7. Tamper with commitment => verification fails
	var badCommitment bn254.G1Affine
	// Multiply the commitment by a random scalar
	randomScalar, _ := rand.Int(rand.Reader, bn256.Order)
	badCommitment.ScalarMultiplication(&commitment, randomScalar)
	if err := vk.Verify(badCommitment, proof); err != nil {
		fmt.Println("Tampered verify: FAILED (as expected) ->", err)
	} else {
		fmt.Println("Tampered verify: SUCCEEDED (should NOT happen!)")
	}
	fmt.Println()
}

// -----------------------------------------------------------------------------
//
//	Example: Batch Pedersen (Same VK)
//
// -----------------------------------------------------------------------------
func ExampleBatchSameVK() {
	fmt.Println("---- [Batch Pedersen: Same VK] ----")
	_, _, g1aff, _ := Generate()

	// Generate additional G1 points by doubling
	var g12aff, g13aff bn254.G1Affine

	// Double g1aff to get g12aff
	var temp bn254.G1Jac
	temp.FromAffine(&g1aff)
	temp.Double(&temp)
	g12aff.FromJacobian(&temp)

	// Double again to get g13aff
	temp.Double(&temp)
	g13aff.FromJacobian(&temp)

	// We'll do 2 separate commitments, each over 3 field elements
	nbValues := 3
	basis := make([]bn254.G1Affine, nbValues)
	basis[0] = g1aff
	basis[1] = g12aff
	basis[2] = g13aff

	// Create two identical sets of bases
	bases := [][]bn254.G1Affine{basis, basis}

	pk, vk, err := pedersen.Setup(bases)
	if err != nil {
		panic(err)
	}

	// Prepare two different sets of 3 values
	valuesA := []fr.Element{fr.NewElement(10), fr.NewElement(20), fr.NewElement(30)}
	valuesB := []fr.Element{fr.NewElement(100), fr.NewElement(200), fr.NewElement(300)}

	// Commit and prove knowledge separately
	commitA, err := pk[0].Commit(valuesA)
	if err != nil {
		panic(err)
	}
	proofA, err := pk[0].ProveKnowledge(valuesA)
	if err != nil {
		panic(err)
	}

	commitB, err := pk[1].Commit(valuesB)
	if err != nil {
		panic(err)
	}
	proofB, err := pk[1].ProveKnowledge(valuesB)
	if err != nil {
		panic(err)
	}

	// Verify each individually
	if err := vk.Verify(commitA, proofA); err != nil {
		fmt.Println("Verification (A) failed:", err)
	} else {
		fmt.Println("Verification (A) succeeded")
	}
	if err := vk.Verify(commitB, proofB); err != nil {
		fmt.Println("Verification (B) failed:", err)
	} else {
		fmt.Println("Verification (B) succeeded")
	}

	// ----------------
	// Single "BatchProve" -> One proof for both sets
	// ----------------
	combinationCoeff := fr.NewElement(42) // In real usage, from the verifier or via Fiat-Shamir
	values2D := [][]fr.Element{valuesA, valuesB}
	batchProof, err := pedersen.BatchProve(pk, values2D, combinationCoeff)
	if err != nil {
		panic(err)
	}

	// We also fold the two commitments into one
	commitFold := bn254.G1Affine{}
	commitFold.Set(&commitA)
	// fold commitB with the same combination coefficient
	var commitBScaled bn254.G1Jac
	commitBScaled.FromAffine(&commitB)
	commitBScaled.ScalarMultiplication(&commitBScaled, combinationCoeff.BigInt(new(big.Int)))
	var temp2 bn254.G1Affine
	temp2.FromJacobian(&commitBScaled)
	commitFold.Add(&commitFold, &temp2)

	// Verify the folded commitment + single batch proof
	if err := vk.Verify(commitFold, batchProof); err != nil {
		fmt.Println("Batch Verify (same VK) failed:", err)
	} else {
		fmt.Println("Batch Verify (same VK) succeeded")
	}
	fmt.Println()
}

// -----------------------------------------------------------------------------
//
//	Example: Batch Pedersen with Multiple VKs
//
// -----------------------------------------------------------------------------
func ExampleBatchMultiVK() {
	fmt.Println("---- [Batch Pedersen: Multiple VK Example] ----")

	// 1) Create random generators to share
	_, _, g1aff, g2aff := Generate()

	// Generate additional G1 points by doubling
	var g12aff, g13aff, g14aff bn254.G1Affine

	// Double g1aff to get g12aff
	var temp bn254.G1Jac
	temp.FromAffine(&g1aff)
	temp.Double(&temp)
	g12aff.FromJacobian(&temp)

	// Double again to get g13aff
	temp.Double(&temp)
	g13aff.FromJacobian(&temp)

	// Double once more to get g14aff
	temp.Double(&temp)
	g14aff.FromJacobian(&temp)

	// 2) Setup #1 with first two G1 points
	basis1 := []bn254.G1Affine{g1aff, g12aff}
	pk1, vk1, err := pedersen.Setup(
		[][]bn254.G1Affine{basis1},
		pedersen.WithG2Point(g2aff),
	)
	if err != nil {
		panic(err)
	}

	// 3) Setup #2 with next two G1 points
	basis2 := []bn254.G1Affine{g13aff, g14aff}
	pk2, vk2, err := pedersen.Setup(
		[][]bn254.G1Affine{basis2},
		pedersen.WithG2Point(g2aff), // using same G2
	)
	if err != nil {
		panic(err)
	}

	// 4) Commit + Prove for each setup
	values1 := []fr.Element{fr.NewElement(11), fr.NewElement(22)}
	commit1, _ := pk1[0].Commit(values1)
	proof1, _ := pk1[0].ProveKnowledge(values1)

	values2 := []fr.Element{fr.NewElement(33), fr.NewElement(44)}
	commit2, _ := pk2[0].Commit(values2)
	proof2, _ := pk2[0].ProveKnowledge(values2)

	// 5) Now we do BatchVerifyMultiVk with both verifying keys
	vkArr := []pedersen.VerifyingKey{vk1, vk2}
	commitArr := []bn254.G1Affine{commit1, commit2}
	proofArr := []bn254.G1Affine{proof1, proof2}
	comboCoeff := fr.NewElement(7) // random or FS-challenge

	// Should SUCCEED if we used the same G2 generator
	if err := pedersen.BatchVerifyMultiVk(vkArr, commitArr, proofArr, comboCoeff); err != nil {
		fmt.Println("BatchVerifyMultiVk => FAILED:", err)
	} else {
		fmt.Println("BatchVerifyMultiVk => SUCCEEDED!")
	}

	// 6) Tamper with second proof => fail
	badProof2 := proof2
	var randScalar big.Int
	randScalar.SetUint64(9999)
	badProof2.ScalarMultiplication(&badProof2, &randScalar)
	if err := pedersen.BatchVerifyMultiVk(vkArr, commitArr, []bn254.G1Affine{proof1, badProof2}, comboCoeff); err != nil {
		fmt.Println("BatchVerifyMultiVk with bad proof => FAIL (as expected):", err)
	} else {
		fmt.Println("BatchVerifyMultiVk with bad proof => SUCCEEDED (should NOT happen!)")
	}
	fmt.Println()
}

// -----------------------------------------------------------------------------

func PedersenTest() {
	ExampleSinglePedersen()
	ExampleBatchSameVK()
	ExampleBatchMultiVK()
}

func Generate() (g1Jac bn254.G1Jac, g2Jac bn254.G2Jac, g1Aff bn254.G1Affine, g2Aff bn254.G2Affine) {
	return bn254.Generators()
}
