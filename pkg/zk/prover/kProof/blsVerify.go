package kProof

import (
	"embed"
	"fmt"
	"log"
	"math/big"
	"os"
	"text/template"

	"github.com/consensys/gnark-crypto/ecc"
	eddsa_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	eddsa_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	eddsa_bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
)

//go:embed template/*.tmpl
var eddsaTemplateFiles embed.FS

// ---------------------------------------------------------------------------
// Circuit for ownership of a secret key (placeholder logic)

type Circuit struct {
	// typical EDDSA twisted edwards coords
	Pk struct {
		A struct {
			X frontend.Variable
			Y frontend.Variable
		}
	}
	// We'll store chunk1 and chunk2 (each a 128-bit portion, for example)
	SkChunk1 frontend.Variable
	SkChunk2 frontend.Variable
}

type TemplateData struct {
	Name    ecc.ID
	Package string
	EnumID  string
}

func (c *Circuit) Define(api frontend.API) error {
	// Compute 2^128 as a *big.Int constant.
	exp128 := new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil)

	// Reconstruct private key = chunk1 * 2^128 + chunk2
	fullSk := api.Add(api.Mul(c.SkChunk1, exp128), c.SkChunk2)

	// Dummy check: sum of x+y must equal fullSk
	sum := api.Add(c.Pk.A.X, c.Pk.A.Y)
	api.AssertIsEqual(sum, fullSk)

	return nil
}

// parseKeys is just an example; you can adapt to real usage
func parseKeys(id ecc.ID, pubKeyBuf []byte, privKeyBuf []byte) ([]byte, []byte, []byte) {
	switch id {
	case ecc.BN254:
		var priv eddsa_bn254.G1Affine
		priv.SetBytes(privKeyBuf)
		aX := priv.X.Bytes()
		aY := priv.Y.Bytes()
		scalar := privKeyBuf[:32]
		return aX[:], aY[:], scalar[:]

	case ecc.BLS12_381:
		var priv eddsa_bls12381.G1Affine
		priv.SetBytes(privKeyBuf)
		aX := priv.X.Bytes()
		aY := priv.Y.Bytes()
		scalar := privKeyBuf[:32]
		return aX[:], aY[:], scalar[:]

	case ecc.BLS12_377:
		var priv eddsa_bls12377.G1Affine
		priv.SetBytes(privKeyBuf)
		aX := priv.X.Bytes()
		aY := priv.Y.Bytes()
		scalar := privKeyBuf[:32]
		return aX[:], aY[:], scalar[:]
	case ecc.BW6_761:
		var priv bw6761.G1Affine
		priv.SetBytes(privKeyBuf)
		aX := priv.X.Bytes()
		aY := priv.Y.Bytes()
		scalar := privKeyBuf[:32]
		return aX[:], aY[:], scalar[:]
	default:
		// fallback
		return pubKeyBuf, pubKeyBuf, privKeyBuf
	}
}

func generateTemplate(prod string, fs embed.FS) error {
	tmpl := template.New(prod)
	// IMPORTANT: use .EnumID in the .tmpl to compare strings like "bw6_761"
	tmpl.ParseFS(
		fs,
		"template/eddsa.go.tmpl",
		"template/eddsa.test.go.tmpl",
		"template/marshal.go.tmpl",
		"template/doc.go.tmpl",
	)

	for _, curve := range SignatureSchemeImplemented() {
		data := TemplateData{
			Name:    curve,
			Package: "verifyKey",
			EnumID:  curve.String(), // e.g. "bn254", "bls12_377", "bw6_761", etc.
		}

		f, err := os.Create("./generated_" + curve.String() + "_" + prod + ".go")
		if err != nil {
			log.Fatalf("error creating file %s: %v", "generated_"+curve.String()+"_"+prod+".go", err)
		}
		defer f.Close()

		if err := tmpl.ExecuteTemplate(f, "eddsa.go.tmpl", data); err != nil {
			fmt.Println("error executing template eddsa.go.tmpl: ", err)
		}
		if err := tmpl.ExecuteTemplate(f, "doc.go.tmpl", data); err != nil {
			fmt.Println("error executing template doc.go.tmpl: ", err)
		}
		if err := tmpl.ExecuteTemplate(f, "eddsa.test.go.tmpl", data); err != nil {
			fmt.Println("error executing template eddsa.test.go.tmpl: ", err)
		}
		if err := tmpl.ExecuteTemplate(f, "marshal.go.tmpl", data); err != nil {
			fmt.Println("error executing template marshal.go.tmpl: ", err)
		}
	}
	return nil
}

func BlsVerify() {
	eccs := ecc.Implemented()
	fmt.Println("Available curves in gnark-crypto:", eccs)

	// Example of parsing embedded templates
	err := generateTemplate("prod", eddsaTemplateFiles)
	if err != nil {
		log.Fatalf("error generating template: %v", err)
	}

}

func SignatureSchemeImplemented() []ecc.ID {
	return []ecc.ID{
		ecc.BN254,
		ecc.BLS12_381,
		ecc.BLS12_377,
		ecc.BW6_761,
	}
}
