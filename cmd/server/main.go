package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/yesmishgan/test-snark/internal/pb/api"
	"github.com/yesmishgan/test-snark/internal/server"
)

// -------------------------------------------------------------------------------------------------
// flags
var (
	fCircuitDir  = flag.String("circuit_dir", "./circuits", "circuits root directory")
	fCertFile    = flag.String("cert_file", "./certs/gnarkd.crt", "TLS cert file")
	fKeyFile     = flag.String("key_file", "./certs/gnarkd.key", "TLS key file")
	fgRPCPort    = flag.Int("grpc_port", 9002, "gRPC server port")
	fWitnessPort = flag.Int("witness_port", 9001, "witness tcp socket port")
)

// -------------------------------------------------------------------------------------------------
// logger
var (
	logger *zap.Logger
	log    *zap.SugaredLogger
)

// -------------------------------------------------------------------------------------------------
// init logger
func init() {
	var err error
	logger, err = newZapConfig().Build()
	if err != nil {
		fmt.Println("unable to create logger")
		os.Exit(1)
	}
	log = logger.Sugar()
}

// protoc --experimental_allow_proto3_optional --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative  pb/gnarkd.proto
func main() {
	log.Info("starting gnarkd")
	defer log.Warn("stopping gnarkd")
	defer logger.Sync() // flushes buffer, if any

	// catch sigterm and sigint.
	chDone := make(chan os.Signal)
	signal.Notify(chDone, syscall.SIGTERM, syscall.SIGINT)

	// Parse flags
	flag.Parse()

	gnarkdServer, err := server.NewServer(log, *fCircuitDir)
	if err != nil {
		log.Fatalw("couldn't init gnarkd", "err", err)
	}

	// ---------------------------------------------------------------------------------------------
	// gRPC endpoint
	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", *fgRPCPort))
	if err != nil {
		log.Fatalw("failed to listen tcp", "err", err)
	}
	creds, err := credentials.NewServerTLSFromFile(*fCertFile, *fKeyFile)
	if err != nil {
		log.Fatalw("failed to setup TLS", "err", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterGroth16Server(s, gnarkdServer)

	go func() {
		defer signal.Stop(chDone)
		<-chDone

		// clean up  if SIGINT or SIGTERM is caught.
		s.GracefulStop()
	}()

	if err := s.Serve(grpcLis); err != nil {
		log.Fatalw("failed to start server", "err", err)
	}
}

func newZapConfig() zap.Config {
	return zap.Config{
		Level:       zap.NewAtomicLevelAt(zap.DebugLevel),
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          "console",
		EncoderConfig:     zap.NewDevelopmentEncoderConfig(),
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
	}
}
