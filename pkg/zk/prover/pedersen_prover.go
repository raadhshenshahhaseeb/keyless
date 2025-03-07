package circuit

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"github.com/consensys/gnark/frontend"
	"github.com/hblocks/keyless/pkg/commitment"

	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/test"
)

type Circuit struct {
	VK []struct {
		G struct {
			X frontend.Variable
			Y frontend.Variable
		}
	} `gnark:"public"`
	Commitments []struct {
		X frontend.Variable
		Y frontend.Variable
	} `gnark:"secret"`
	Proofs []struct {
		X frontend.Variable
		Y frontend.Variable
	} `gnark:"secret"`
	CombinationCoeff fr.Element `gnark:"secret"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	n := len(circuit.VK)
	if len(circuit.Commitments) != n || len(circuit.Proofs) != n {
		return fmt.Errorf("invalid input lengths")
	}

	for i := 0; i < n; i++ {
		// Verify commitment matches proof
		api.AssertIsEqual(circuit.Commitments[i].X, circuit.Proofs[i].X)
		api.AssertIsEqual(circuit.Commitments[i].Y, circuit.Proofs[i].Y)
	}

	return nil
}

func Prover(assignment *Circuit) {
	circuit, _ := ecgo.Compile(ecc.BN254.ScalarField(), assignment)
	c := circuit.GetLayeredCircuit()
	os.WriteFile("circuit.txt", c.Serialize(), 0o644)
	inputSolver := circuit.GetInputSolver()
	witness, _ := inputSolver.SolveInputAuto(assignment)
	os.WriteFile("witness.txt", witness.Serialize(), 0o644)
	if !test.CheckCircuit(c, witness) {
		panic("verification failed")
	}
}

// PedersenProver demonstrates Pedersen commitments with multiple verification keys
// and batch verification. It returns error on failure or nil on success.
func PedersenProver() (*Circuit, error) {
	fmt.Println("---- [Batch Pedersen: Multiple VK Example] ----")

	// 1) Create random generators to share
	_, _, g1aff, g2aff := commitment.Generate()

	// Generate a sequence of G1 points by doubling
	g1Points := make([]bn254.G1Affine, 4)
	g1Points[0] = g1aff

	var temp bn254.G1Jac
	temp.FromAffine(&g1aff)

	for i := 1; i < 4; i++ {
		temp.Double(&temp)
		g1Points[i].FromJacobian(&temp)
	}

	// 2) Setup #1 with first two G1 points
	basis1 := []bn254.G1Affine{g1Points[0], g1Points[1]}
	pk1, vk1, err := pedersen.Setup(
		[][]bn254.G1Affine{basis1},
		pedersen.WithG2Point(g2aff),
	)
	if err != nil {
		return nil, fmt.Errorf("setup #1 failed: %w", err)
	}

	// 3) Setup #2 with next two G1 points
	basis2 := []bn254.G1Affine{g1Points[2], g1Points[3]}
	pk2, vk2, err := pedersen.Setup(
		[][]bn254.G1Affine{basis2},
		pedersen.WithG2Point(g2aff), // using same G2
	)
	if err != nil {
		return nil, fmt.Errorf("setup #2 failed: %w", err)
	}

	// 4) Create commitments and proofs
	values1 := []fr.Element{fr.NewElement(11), fr.NewElement(22)}
	commit1, err := pk1[0].Commit(values1)
	if err != nil {
		return nil, fmt.Errorf("commit #1 failed: %w", err)
	}

	proof1, err := pk1[0].ProveKnowledge(values1)
	if err != nil {
		return nil, fmt.Errorf("prove #1 failed: %w", err)
	}

	values2 := []fr.Element{fr.NewElement(33), fr.NewElement(44)}
	commit2, err := pk2[0].Commit(values2)
	if err != nil {
		return nil, fmt.Errorf("commit #2 failed: %w", err)
	}

	proof2, err := pk2[0].ProveKnowledge(values2)
	if err != nil {
		return nil, fmt.Errorf("prove #2 failed: %w", err)
	}

	// 5) Batch verification with both verifying keys
	vkArr := []pedersen.VerifyingKey{vk1, vk2}
	commitArr := []bn254.G1Affine{commit1, commit2}
	proofArr := []bn254.G1Affine{proof1, proof2}
	comboCoeff := fr.NewElement(6) // random or FS-challenge

	// Verify valid proofs
	if err := pedersen.BatchVerifyMultiVk(vkArr, commitArr, proofArr, comboCoeff); err != nil {
		return nil, fmt.Errorf("batch verification failed: %w", err)
	}
	fmt.Println("BatchVerifyMultiVk => SUCCEEDED!")

	// 6) Tamper with second proof to demonstrate failure case
	badProof2 := proof2
	var randScalar big.Int
	randScalar.SetUint64(9999)
	badProof2.ScalarMultiplication(&badProof2, &randScalar)

	err = pedersen.BatchVerifyMultiVk(vkArr, commitArr, []bn254.G1Affine{proof1, badProof2}, comboCoeff)
	if err == nil {
		return nil, fmt.Errorf("batch verification with tampered proof succeeded when it should fail")
	}
	fmt.Println("BatchVerifyMultiVk with bad proof => FAIL (as expected):", err)

	fmt.Println()
	return &Circuit{
		VK: []struct {
			G struct {
				X frontend.Variable
				Y frontend.Variable
			}
		}{{G: struct {
			X frontend.Variable
			Y frontend.Variable
		}{X: vk1.G.X, Y: vk1.G.Y}}, {G: struct {
			X frontend.Variable
			Y frontend.Variable
		}{X: vk2.G.X, Y: vk2.G.Y}}},
		Commitments: []struct {
			X frontend.Variable
			Y frontend.Variable
		}{{X: commit1.X, Y: commit1.Y}, {X: commit2.X, Y: commit2.Y}},
		Proofs: []struct {
			X frontend.Variable
			Y frontend.Variable
		}{{X: proof1.X, Y: proof1.Y}, {X: proof2.X, Y: proof2.Y}},
		CombinationCoeff: comboCoeff,
	}, nil
}
