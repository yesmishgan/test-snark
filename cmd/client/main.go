package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/frontend"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/yesmishgan/test-snark/internal/circuit"
	"github.com/yesmishgan/test-snark/internal/pb/api"
)

const (
	address = "127.0.0.1:9002"
)

func main() {
	config := &tls.Config{
		// TODO add CA cert
		InsecureSkipVerify: true,
	}

	// Set up a connection to the server.
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	if err != nil {
		log.Fatal(err)
	}
	c := pb.NewGroth16Client(conn)

	ctx := context.Background()

	var w cubic.Circuit
	w.X = 3
	w.Y = 35

	witness, _ := frontend.NewWitness(&w, ecc.BN254.ScalarField())

	circuits, err := circuit.LoadCircuits("./circuits")
	if err != nil {
		log.Fatalf("failed to load circuits from %s", "./circuits")
	}

	selectedCircuit := circuits["bn254/cubic"]

	proof, err := groth16.Prove(selectedCircuit.R1cs, selectedCircuit.Pk, witness)

	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)

	var pBuf bytes.Buffer

	publicWithess, _ := witness.Public()
	publicWithess.WriteTo(&pBuf)

	result, err := c.Verify(ctx, &pb.VerifyRequest{
		CircuitID:     "bn254/cubic",
		Proof:         proofBuf.Bytes(),
		PublicWitness: pBuf.Bytes(),
	})
	if err != nil {
		log.Fatalf("failed to verify: %s", err)
	}

	log.Printf("verify result: %t", result.GetOk())
}
