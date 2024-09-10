package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/yesmishgan/test-snark/utils/circuits/bn254/cubic"
)

func main() {
	var circuit cubic.Circuit
	r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	{
		f, err := os.Create("circuits/bn254/cubic/cubic.r1cs")
		r1cs.WriteTo(f)
		f.Close()
		fmt.Print(err)
	}

	pk, vk, _ := groth16.Setup(r1cs)
	{
		f, _ := os.Create("circuits/bn254/cubic/cubic.pk")
		pk.WriteTo(f)
		f.Close()
	}
	{
		f, _ := os.Create("circuits/bn254/cubic/cubic.vk")
		vk.WriteTo(f)
		f.Close()
	}
}
