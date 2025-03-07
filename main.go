package main

import (
	circuit "github.com/hblocks/keyless/pkg/zk/prover"
)

func main() {
	cc, err := circuit.PedersenProver()
	if err != nil {
		panic(err)
	}

	circuit.Prover(cc)
}
