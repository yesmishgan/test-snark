package server

import (
	"errors"
	"github.com/yesmishgan/test-snark/internal/circuit"
	"github.com/yesmishgan/test-snark/internal/pb/api"
	"go.uber.org/zap"
)

// Server implements Groth16Server
type Server struct {
	pb.UnimplementedGroth16Server
	circuits   map[string]circuit.Circuit // not thread safe as it is loaded once only
	log        *zap.SugaredLogger
	circuitDir string
}

// NewServer returns a server implementing the service as defined in pb/gnarkd.proto
func NewServer(log *zap.SugaredLogger, circuitDir string) (*Server, error) {
	if log == nil {
		return nil, errors.New("please provide a logger")
	}
	s := &Server{
		log:        log,
		circuitDir: circuitDir,
	}

	circuits, err := circuit.LoadCircuits(circuitDir)
	if err != nil {
		return nil, err
	}

	s.circuits = circuits
	return s, nil
}
