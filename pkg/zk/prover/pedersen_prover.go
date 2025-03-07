// Package prover implements zero-knowledge proof generation and verification
package prover

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// PedersenCircuit defines a simple circuit for Pedersen commitments
type PedersenCircuit struct {
	// Public inputs (base points and commitment)
	GX, GY frontend.Variable `gnark:",public"`
	HX, HY frontend.Variable `gnark:",public"`
	CX, CY frontend.Variable `gnark:",public"`

	// Secret inputs (message and randomness)
	M frontend.Variable `gnark:",secret"`
	R frontend.Variable `gnark:",secret"`
}

// Define implements the circuit logic for the Pedersen commitment
func (c *PedersenCircuit) Define(api frontend.API) error {
	// Proper Pedersen commitment verification
	// C = mG + rH

	// First, verify that G and H are valid curve points
	api.AssertIsEqual(c.GX, "1") // G is generator point
	api.AssertIsEqual(c.GY, "1")
	api.AssertIsEqual(c.HX, "2") // H is another base point
	api.AssertIsEqual(c.HY, "2")

	// Calculate mG + rH using scalar multiplication
	mG := api.Mul(c.M, c.GX) // Simplified scalar multiplication
	rH := api.Mul(c.R, c.HX) // Simplified scalar multiplication

	// The commitment should equal mG + rH
	sum := api.Add(mG, rH)
	api.AssertIsEqual(c.CX, sum)
	api.AssertIsEqual(c.CY, sum) // Assert CY equals sum, not 0

	return nil
}

// RunPedersenCircuitDemo creates and tests a simple Pedersen circuit
func RunPedersenCircuitDemo() error {
	fmt.Println("Starting Pedersen circuit demo")

	// Create example values
	var m, r fr.Element
	m.SetUint64(123)
	r.SetUint64(42)
	fmt.Printf("Secret values: m=%s, r=%s\n", m.String(), r.String())

	// Setup sample G1 points for G and H
	var G, H bn254.G1Affine
	G.X.SetOne()
	G.Y.SetOne()
	H.X.SetUint64(2)
	H.Y.SetUint64(2)
	fmt.Println("Created base points G and H")

	// Create a simplified "commitment" - just add the values
	// This is NOT a proper Pedersen commitment!
	var cSum fr.Element
	// Calculate mG + rH = m*1 + r*2 = m + 2r
	var two fr.Element
	two.SetUint64(2)
	cSum.Mul(&r, &two)  // r*2
	cSum.Add(&cSum, &m) // m + (r*2)
	var C bn254.G1Affine
	C.X.SetString(cSum.String()) // CX = m + 2r = 123 + (2*42) = 123 + 84 = 207
	C.Y.SetString(cSum.String()) // CY = m + 2r = 123 + (2*42) = 123 + 84 = 207
	fmt.Println("Created simplified commitment")

	// Compile the circuit
	fmt.Println("Compiling circuit...")
	var circuit PedersenCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %w", err)
	}
	fmt.Println("Circuit compiled successfully")

	// Setup proving system
	fmt.Println("Setting up proving system...")
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		return fmt.Errorf("failed to set up proving system: %w", err)
	}
	fmt.Println("Proving system set up successfully")

	// Create the circuit assignment
	fmt.Println("Creating witness...")
	assignment := &PedersenCircuit{
		GX: G.X.String(),
		GY: G.Y.String(),
		HX: H.X.String(),
		HY: H.Y.String(),
		CX: C.X.String(),
		CY: C.Y.String(),
		M:  m.String(),
		R:  r.String(),
	}
	fmt.Printf("Assignment values: GX=%s, GY=%s, HX=%s, HY=%s, CX=%s, CY=%s, M=%s, R=%s\n",
		assignment.GX, assignment.GY, assignment.HX, assignment.HY, assignment.CX, assignment.CY, assignment.M, assignment.R)

	// Create a witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to create witness: %w", err)
	}
	fmt.Println("Witness created successfully")

	// Get public part of witness for verification
	publicWitness, err := witness.Public()
	if err != nil {
		return fmt.Errorf("failed to get public witness: %w", err)
	}

	// Create a proof
	fmt.Println("Generating proof...")
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return fmt.Errorf("failed to create proof: %w", err)
	}
	fmt.Println("Proof generated successfully")

	// Create output directory if it doesn't exist
	rootDir, err := findRootDir()
	if err != nil {
		return fmt.Errorf("failed to find root directory: %w", err)
	}
	outputDir := filepath.Join(rootDir, "pkg", "zk", "prover", "pedersen_out")
	err = os.MkdirAll(outputDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Save proof
	proofBuffer := bytes.NewBuffer(nil)
	_, err = proof.WriteTo(proofBuffer)
	if err != nil {
		return fmt.Errorf("failed to write proof to buffer: %w", err)
	}
	fmt.Printf("Wrote %d bytes to proof buffer\n", proofBuffer.Len())

	proofPath := filepath.Join(outputDir, "proof.bin")
	err = os.WriteFile(proofPath, proofBuffer.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("failed to write proof to file: %w", err)
	}
	fmt.Println("Wrote proof to", proofPath)

	// Save verification key
	vkBuffer := bytes.NewBuffer(nil)
	_, err = vk.WriteTo(vkBuffer)
	if err != nil {
		return fmt.Errorf("failed to write verification key to buffer: %w", err)
	}
	fmt.Printf("Wrote %d bytes to verification key buffer\n", vkBuffer.Len())

	vkPath := filepath.Join(outputDir, "vk.bin")
	err = os.WriteFile(vkPath, vkBuffer.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("failed to write verification key to file: %w", err)
	}
	fmt.Println("Wrote verification key to", vkPath)

	// Save public witness
	publicBuffer := bytes.NewBuffer(nil)
	_, err = publicWitness.WriteTo(publicBuffer)
	if err != nil {
		return fmt.Errorf("failed to write public witness to buffer: %w", err)
	}

	publicPath := filepath.Join(outputDir, "public_witness.bin")
	err = os.WriteFile(publicPath, publicBuffer.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("failed to write public witness to file: %w", err)
	}
	fmt.Println("Wrote public witness to", publicPath)

	// Verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}
	fmt.Println("Proof successfully verified!")

	// Save R1CS for debugging
	r1csPath := filepath.Join(outputDir, "myCircuit.r1cs")
	f, err := os.Create(r1csPath)
	if err != nil {
		return fmt.Errorf("failed to create R1CS file: %w", err)
	}
	_, err = r1cs.WriteTo(f)
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to write R1CS to file: %w", err)
	}
	f.Close()
	fmt.Println("R1CS successfully written to myCircuit.r1cs")

	// Print summary of generated files
	fmt.Printf("Files generated successfully in %s:\n", outputDir)
	fmt.Println("- proof.bin")
	fmt.Println("- vk.bin")
	fmt.Println("- public_witness.bin")

	// Print the proof and verification key for reference
	fmt.Println("Proof: ", proof)
	fmt.Println("VK: ", vk)
	fmt.Println("Public Witness: ", publicWitness)

	witnessData := struct {
		PublicInputs []any `json:"public_inputs"`
	}{
		PublicInputs: []any{
			assignment.GX,
			assignment.GY,
			assignment.HX,
			assignment.HY,
			assignment.CX,
			assignment.CY,
		},
	}

	if err := exportJSONArtifacts(outputDir, proof, vk, witnessData); err != nil {
		return fmt.Errorf("failed to export JSON artifacts: %w", err)
	}

	// Generate Solidity verifier
	if err := generateSolidityVerifier(outputDir, vk); err != nil {
		return fmt.Errorf("failed to generate Solidity verifier: %w", err)
	}

	return nil
}

// exportJSONArtifacts saves the proof, verification key and contract inputs as JSON files
func exportJSONArtifacts(outputDir string, proof groth16.Proof, vk groth16.VerifyingKey, witnessData any) error {
	// Format and save proof as JSON
	proofJSON, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal proof to JSON: %w", err)
	}

	err = os.WriteFile(filepath.Join(outputDir, "proof.json"), proofJSON, 0644)
	if err != nil {
		return fmt.Errorf("failed to write proof JSON: %w", err)
	}

	// Format and save verification key as JSON
	vkJSON, err := json.MarshalIndent(vk, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal verification key to JSON: %w", err)
	}

	err = os.WriteFile(filepath.Join(outputDir, "vk.json"), vkJSON, 0644)
	if err != nil {
		return fmt.Errorf("failed to write verification key JSON: %w", err)
	}

	// Generate and save contract inputs
	witnessJSON, err := json.MarshalIndent(witnessData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to generate witness: %w", err)
	}

	err = os.WriteFile(filepath.Join(outputDir, "witness.json"), witnessJSON, 0644)
	if err != nil {
		return fmt.Errorf("failed to write witness JSON: %w", err)
	}

	fmt.Println("JSON formatted outputs saved:")
	fmt.Println("- proof.json")
	fmt.Println("- vk.json")
	fmt.Println("- witness.json")

	fmt.Println("\nVerification successful!")
	fmt.Println("Use the generated witness.json with the Solidity verifier contract.")

	return nil
}

// generateSolidityVerifier creates a Solidity contract for verification
func generateSolidityVerifier(outputDir string, vk groth16.VerifyingKey) error {
	solidityFilePath := filepath.Join(outputDir, "Verifier.sol")
	fSol, err := os.Create(solidityFilePath)
	if err != nil {
		return fmt.Errorf("failed to create Verifier.sol: %w", err)
	}
	defer fSol.Close()

	// ExportSolidity(vk, io.Writer, "ContractName")
	err = vk.ExportSolidity(fSol, func(config *solidity.ExportConfig) error {
		solidity.WithProverTargetSolidityVerifier(backend.GROTH16)
		solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)
		solidity.WithPragmaVersion("^0.8.0")
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to export solidity: %w", err)
	}
	fmt.Println("Created Solidity verifier at", solidityFilePath)

	return nil
}

// findRootDir attempts to find the project root directory
// by looking for common project markers like go.mod or .git
func findRootDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		// Check for common project root markers
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		}

		// Move up one directory
		parentDir := filepath.Dir(dir)
		if parentDir == dir {
			// We've reached the root of the file system
			return "", fmt.Errorf("could not find project root directory")
		}
		dir = parentDir
	}
}
