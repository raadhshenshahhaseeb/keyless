package main

import (
	"fmt"
	"github.com/hblocks/keyless/pkg/commitment"
)

func main() {
	//kProof.BlsVerify()
	commitment.KzgCommitment()
	commitment.KzgCommitmentAndVerificationDemo()

	fmt.Println("////////////////////////////pedersen demo")
	commitment.PedersenTest()
}
