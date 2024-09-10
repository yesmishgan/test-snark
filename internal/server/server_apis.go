package server

import (
	"bytes"
	"context"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/yesmishgan/test-snark/internal/pb/api"
)

// Prove takes circuitID and witness as parameter
// this is a synchronous call and bypasses the job queue
// it is meant to be used for small circuits, for larger circuits (proving time) and witnesses,
// use CreateProveJob instead
func (s *Server) Prove(ctx context.Context, request *pb.ProveRequest) (*pb.ProveResult, error) {
	s.log.Warnw("Prove", "circuitID", request.CircuitID)

	// get circuit
	circuit, ok := s.circuits[request.CircuitID]
	if !ok {
		s.log.Errorw("Prove called with unknown circuitID", "circuitID", request.CircuitID)
		return nil, status.Errorf(codes.NotFound, "unknown circuit %s", request.CircuitID)
	}

	w, _ := witness.New(ecc.BN254.ScalarField())
	w.UnmarshalBinary(request.GetWitness())

	// call groth16.Prove with witness
	proof, err := groth16.Prove(circuit.R1cs, circuit.Pk, w)
	if err != nil {
		s.log.Error(err)
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	// serialize proof
	var buf bytes.Buffer
	_, err = proof.WriteTo(&buf)
	if err != nil {
		s.log.Error(err)
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	// return proof
	s.log.Infow("successfully created proof", "circuitID", request.CircuitID)
	return &pb.ProveResult{Proof: buf.Bytes()}, nil
}

// Verify takes circuitID, proof and public witness as parameter
// this is a synchronous call
func (s *Server) Verify(ctx context.Context, request *pb.VerifyRequest) (*pb.VerifyResult, error) {
	s.log.Warnw("Verify", "circuitID", request.CircuitID)

	// get circuit
	circuit, ok := s.circuits[request.CircuitID]
	if !ok {
		s.log.Errorw("Verify called with unknown circuitID", "circuitID", request.CircuitID)
		return nil, status.Errorf(codes.NotFound, "unknown circuit %s", request.CircuitID)
	}

	// call groth16.Verify with witness
	proof := groth16.NewProof(circuit.Pk.CurveID())
	if _, err := proof.ReadFrom(bytes.NewReader(request.Proof)); err != nil {
		s.log.Error(err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	w, _ := witness.New(ecc.BN254.ScalarField())
	w.UnmarshalBinary(request.GetPublicWitness())

	err := groth16.Verify(proof, circuit.Vk, w)
	if err != nil {
		s.log.Error(err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	// return proof
	s.log.Infow("successfully verified proof", "circuitID", request.CircuitID)
	return &pb.VerifyResult{Ok: true}, nil
}
