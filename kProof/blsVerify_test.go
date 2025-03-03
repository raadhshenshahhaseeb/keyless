package kProof

import (
	"embed"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

//go:embed template/*.tmpl
var eddsaTemplateFiles_test embed.FS

func BlsVerifyTest(t *testing.T) {
	eccs := ecc.Implemented()
	fmt.Println("Available curves in gnark-crypto:", eccs)

	t.Run("TestOwnershipSk", func(t *testing.T) {
		assert := test.NewAssert(t)
		// Example of parsing embedded templates
		err := generateTemplate("test", eddsaTemplateFiles_test)
		if err != nil {
			log.Fatalf("error generating template: %v", err)
		}

		for _, id := range SignatureSchemeImplemented() {

			src := rand.NewSource(0)
			r := rand.New(src)

			// ~~~~~ 1) Compile the circuit
			ownershipSkCircuit := &Circuit{
				Pk: struct {
					A struct {
						X frontend.Variable
						Y frontend.Variable
					}
				}{},
				SkChunk1: frontend.Variable(0),
				SkChunk2: frontend.Variable(0),
			}
			_, err := frontend.Compile(id.ScalarField(), r1cs.NewBuilder, ownershipSkCircuit)
			assert.NoError(err)

			// ~~~~~ 2) Get pubkey + privkey (stub).
			// In real code, you'd call something like: privKey, _ := eddsa.New(id, r)
			// or you must define signatures[id] properly. For now, just skip or stub.
			// We'll do a trivial approach:

			// Suppose privKeyBuf is some random 48 bytes (largest case).
			// We'll pretend the last 32 or 48 are the actual scalar.
			fakePriv := make([]byte, 48)
			r.Read(fakePriv)
			fakePub := make([]byte, 64) // or whatever
			r.Read(fakePub)

			pubkeyAx, pubkeyAy, privScalar := parseKeys(id, fakePub, fakePriv)

			// ~~~~~ 3) Construct the witness
			witness := &Circuit{}
			witness.Pk.A.X = pubkeyAx
			witness.Pk.A.Y = pubkeyAy

			// chunk1 = first 16 bytes => big.Int
			chunk1 := new(big.Int).SetBytes(privScalar[:16])
			chunk2 := new(big.Int).SetBytes(privScalar[16:32]) // or [16:48] for BW6_761
			witness.SkChunk1 = chunk1
			witness.SkChunk2 = chunk2

			// ~~~~~ 4) Solve & Prove
			assert.SolvingSucceeded(ownershipSkCircuit, witness)
			assert.ProverSucceeded(ownershipSkCircuit, witness)
		}
	})
}
