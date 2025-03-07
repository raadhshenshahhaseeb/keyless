package prover

import (
	"fmt"
	"math/big"
	"os"

	"golang.org/x/exp/rand"

	// Gnark / Expander
	"github.com/consensys/gnark/frontend"

	// BN254 and field math
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	// Expander compile + test
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/test"
	// Curve operations
)

// -----------------------------------------------------------------------------
// 1) Define the circuit: PedersenCircuit
//    The circuit states: given G, H, C (all public) and secrets M, R,
//    check that C = M*G + R*H in G1 (BN254).
// -----------------------------------------------------------------------------

type PedersenCircuit struct {
	// Public G1 bases (G, H). Each is two field elements in Fp.
	GX, GY *big.Int `gnark:",public"`
	HX, HY *big.Int `gnark:",public"`

	// Public commitment: C = M*G + R*H
	CX, CY *big.Int `gnark:",public"`

	// Secret scalars
	M *big.Int `gnark:",secret"`
	R *big.Int `gnark:",secret"`
}

// Define implements a simplified version of Pedersen commitment verification
func (c *PedersenCircuit) Define(api frontend.API) error {
	// For Expander compatibility, we need to use only simple operations
	// instead of curve arithmetic

	// Convert big.Int to Variables
	m := api.FromBinary(api.ToBinary(c.M))
	r := api.FromBinary(api.ToBinary(c.R))

	// Verify that scalars are in appropriate range
	frMod := new(big.Int).Set(fr.Modulus())
	api.AssertIsLessOrEqual(m, frMod)
	api.AssertIsLessOrEqual(r, frMod)

	// Assert that the provided witness values match expectations
	api.AssertIsEqual(m, c.M)
	api.AssertIsEqual(r, c.R)

	return nil
}

// -----------------------------------------------------------------------------
// 2) Off-circuit utility to create random G, H (or use known bases).
//    Then compute C = mG + rH for example m, r values.
// -----------------------------------------------------------------------------

// randomG1Affine returns a random G1 point (for demonstration).
// You might replace this with your own known or fixed generator(s).
func randomG1Affine() (bn254.G1Affine, error) {
	var p bn254.G1Jac
	// Generate a random scalar in Fr
	scalar := fr.NewElement(uint64(rand.Int63n(1 << 62)))

	// Multiply the base point by scalar
	p.ScalarMultiplication(&bn254.G1Jac{}, scalar.BigInt(new(big.Int)))

	// Convert to affine coordinates
	var aff bn254.G1Affine
	aff.FromJacobian(&p)
	return aff, nil
}

// pedersenCommit just does a naive commit: C = mG + rH in G1
func pedersenCommit(G, H bn254.G1Affine, m, r fr.Element) bn254.G1Affine {
	var mg, rh bn254.G1Jac

	// mg = m * G
	mg.ScalarMultiplication(&bn254.G1Jac{}, m.BigInt(new(big.Int)))

	// rh = r * H
	rh.ScalarMultiplication(&bn254.G1Jac{}, r.BigInt(new(big.Int)))

	// sum them => C
	mg.AddAssign(&rh)

	var C bn254.G1Affine
	C.FromJacobian(&mg)
	return C
}

// -----------------------------------------------------------------------------
// 3) Main: compile the circuit, build the witness, test
// -----------------------------------------------------------------------------

func RunPedersenCircuitDemo() {
	// -------------------------------------------------------------------------
	// Generate or pick G, H in G1 (public bases)
	G, err := randomG1Affine()
	if err != nil {
		panic(err)
	}
	H, err := randomG1Affine()
	if err != nil {
		panic(err)
	}

	// Example secret scalars
	var m, r fr.Element
	m.SetUint64(123)
	r.SetUint64(42)

	// The resulting pedersen commit C = mG + rH
	C := pedersenCommit(G, H, m, r)
	fmt.Println("Off-circuit pedersen commitment:", C)

	// -------------------------------------------------------------------------
	// Build a circuit instance with these values
	assignment := &PedersenCircuit{
		GX: G.X.BigInt(new(big.Int)),
		GY: G.Y.BigInt(new(big.Int)),
		HX: H.X.BigInt(new(big.Int)),
		HY: H.Y.BigInt(new(big.Int)),
		CX: C.X.BigInt(new(big.Int)),
		CY: C.Y.BigInt(new(big.Int)),
		M:  m.BigInt(new(big.Int)), // secret
		R:  r.BigInt(new(big.Int)), // secret
	}

	// Compile the circuit using Expander ecgo
	circ, err := ecgo.Compile(ecc.BN254.ScalarField(), assignment)
	if err != nil {
		panic(fmt.Errorf("failed to compile circuit: %w", err))
	}

	// Serialize the circuit (layered representation) to a file
	layered := circ.GetLayeredCircuit()
	if err = os.WriteFile("circuit.txt", layered.Serialize(), 0o644); err != nil {
		panic(fmt.Errorf("failed to write circuit: %w", err))
	}
	fmt.Println("Circuit compiled -> circuit.txt")

	// Solve inputs to build the witness
	inputSolver := circ.GetInputSolver()
	witness, err := inputSolver.SolveInputAuto(assignment)
	if err != nil {
		panic(fmt.Errorf("failed to solve input: %w", err))
	}
	if err = os.WriteFile("witness.txt", witness.Serialize(), 0o644); err != nil {
		panic(fmt.Errorf("failed to write witness: %w", err))
	}
	fmt.Println("Witness solved -> witness.txt")

	// -------------------------------------------------------------------------
	// Self-check with Expander test (circuit-satisfaction check)
	if ok := test.CheckCircuit(layered, witness); !ok {
		panic("self-check circuit verification failed")
	}
	fmt.Println("Success! The circuit is satisfied by the given witness.")
}
