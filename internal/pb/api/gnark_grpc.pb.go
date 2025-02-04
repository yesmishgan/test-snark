// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.28.0
// source: api/gnark.proto

package pb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	Groth16_Prove_FullMethodName               = "/gnarkd.Groth16/Prove"
	Groth16_Verify_FullMethodName              = "/gnarkd.Groth16/Verify"
	Groth16_CreateProveJob_FullMethodName      = "/gnarkd.Groth16/CreateProveJob"
	Groth16_CancelProveJob_FullMethodName      = "/gnarkd.Groth16/CancelProveJob"
	Groth16_ListProveJob_FullMethodName        = "/gnarkd.Groth16/ListProveJob"
	Groth16_SubscribeToProveJob_FullMethodName = "/gnarkd.Groth16/SubscribeToProveJob"
)

// Groth16Client is the client API for Groth16 service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// Provides services to compute and verify Groth16 proofs
type Groth16Client interface {
	// Prove takes circuitID and witness as parameter
	// this is a synchronous call and bypasses the job queue
	// it is meant to be used for small circuits, for larger circuits (proving time) and witnesses,
	// use CreateProveJob instead
	Prove(ctx context.Context, in *ProveRequest, opts ...grpc.CallOption) (*ProveResult, error)
	// Verify takes circuitID, proof and public witness as parameter
	// this is a synchronous call
	Verify(ctx context.Context, in *VerifyRequest, opts ...grpc.CallOption) (*VerifyResult, error)
	// CreateProveJob enqueue a job into the job queue with WAITING_WITNESS status
	CreateProveJob(ctx context.Context, in *CreateProveJobRequest, opts ...grpc.CallOption) (*CreateProveJobResponse, error)
	// CancelProveJob does what it says it does.
	CancelProveJob(ctx context.Context, in *CancelProveJobRequest, opts ...grpc.CallOption) (*CancelProveJobResponse, error)
	// ListProveJob does what it says it does.
	ListProveJob(ctx context.Context, in *ListProveJobRequest, opts ...grpc.CallOption) (*ListProveJobResponse, error)
	// SubscribeToProveJob enables a client to get job status changes from the server
	// at connection start, server sends current job status
	// when job is done (ok or errored), server closes connection
	SubscribeToProveJob(ctx context.Context, in *SubscribeToProveJobRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[ProveJobResult], error)
}

type groth16Client struct {
	cc grpc.ClientConnInterface
}

func NewGroth16Client(cc grpc.ClientConnInterface) Groth16Client {
	return &groth16Client{cc}
}

func (c *groth16Client) Prove(ctx context.Context, in *ProveRequest, opts ...grpc.CallOption) (*ProveResult, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ProveResult)
	err := c.cc.Invoke(ctx, Groth16_Prove_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *groth16Client) Verify(ctx context.Context, in *VerifyRequest, opts ...grpc.CallOption) (*VerifyResult, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(VerifyResult)
	err := c.cc.Invoke(ctx, Groth16_Verify_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *groth16Client) CreateProveJob(ctx context.Context, in *CreateProveJobRequest, opts ...grpc.CallOption) (*CreateProveJobResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreateProveJobResponse)
	err := c.cc.Invoke(ctx, Groth16_CreateProveJob_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *groth16Client) CancelProveJob(ctx context.Context, in *CancelProveJobRequest, opts ...grpc.CallOption) (*CancelProveJobResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CancelProveJobResponse)
	err := c.cc.Invoke(ctx, Groth16_CancelProveJob_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *groth16Client) ListProveJob(ctx context.Context, in *ListProveJobRequest, opts ...grpc.CallOption) (*ListProveJobResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListProveJobResponse)
	err := c.cc.Invoke(ctx, Groth16_ListProveJob_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *groth16Client) SubscribeToProveJob(ctx context.Context, in *SubscribeToProveJobRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[ProveJobResult], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Groth16_ServiceDesc.Streams[0], Groth16_SubscribeToProveJob_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[SubscribeToProveJobRequest, ProveJobResult]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Groth16_SubscribeToProveJobClient = grpc.ServerStreamingClient[ProveJobResult]

// Groth16Server is the server API for Groth16 service.
// All implementations must embed UnimplementedGroth16Server
// for forward compatibility.
//
// Provides services to compute and verify Groth16 proofs
type Groth16Server interface {
	// Prove takes circuitID and witness as parameter
	// this is a synchronous call and bypasses the job queue
	// it is meant to be used for small circuits, for larger circuits (proving time) and witnesses,
	// use CreateProveJob instead
	Prove(context.Context, *ProveRequest) (*ProveResult, error)
	// Verify takes circuitID, proof and public witness as parameter
	// this is a synchronous call
	Verify(context.Context, *VerifyRequest) (*VerifyResult, error)
	// CreateProveJob enqueue a job into the job queue with WAITING_WITNESS status
	CreateProveJob(context.Context, *CreateProveJobRequest) (*CreateProveJobResponse, error)
	// CancelProveJob does what it says it does.
	CancelProveJob(context.Context, *CancelProveJobRequest) (*CancelProveJobResponse, error)
	// ListProveJob does what it says it does.
	ListProveJob(context.Context, *ListProveJobRequest) (*ListProveJobResponse, error)
	// SubscribeToProveJob enables a client to get job status changes from the server
	// at connection start, server sends current job status
	// when job is done (ok or errored), server closes connection
	SubscribeToProveJob(*SubscribeToProveJobRequest, grpc.ServerStreamingServer[ProveJobResult]) error
	mustEmbedUnimplementedGroth16Server()
}

// UnimplementedGroth16Server must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedGroth16Server struct{}

func (UnimplementedGroth16Server) Prove(context.Context, *ProveRequest) (*ProveResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Prove not implemented")
}
func (UnimplementedGroth16Server) Verify(context.Context, *VerifyRequest) (*VerifyResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Verify not implemented")
}
func (UnimplementedGroth16Server) CreateProveJob(context.Context, *CreateProveJobRequest) (*CreateProveJobResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateProveJob not implemented")
}
func (UnimplementedGroth16Server) CancelProveJob(context.Context, *CancelProveJobRequest) (*CancelProveJobResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CancelProveJob not implemented")
}
func (UnimplementedGroth16Server) ListProveJob(context.Context, *ListProveJobRequest) (*ListProveJobResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListProveJob not implemented")
}
func (UnimplementedGroth16Server) SubscribeToProveJob(*SubscribeToProveJobRequest, grpc.ServerStreamingServer[ProveJobResult]) error {
	return status.Errorf(codes.Unimplemented, "method SubscribeToProveJob not implemented")
}
func (UnimplementedGroth16Server) mustEmbedUnimplementedGroth16Server() {}
func (UnimplementedGroth16Server) testEmbeddedByValue()                 {}

// UnsafeGroth16Server may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to Groth16Server will
// result in compilation errors.
type UnsafeGroth16Server interface {
	mustEmbedUnimplementedGroth16Server()
}

func RegisterGroth16Server(s grpc.ServiceRegistrar, srv Groth16Server) {
	// If the following call pancis, it indicates UnimplementedGroth16Server was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Groth16_ServiceDesc, srv)
}

func _Groth16_Prove_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ProveRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Groth16Server).Prove(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Groth16_Prove_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Groth16Server).Prove(ctx, req.(*ProveRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Groth16_Verify_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Groth16Server).Verify(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Groth16_Verify_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Groth16Server).Verify(ctx, req.(*VerifyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Groth16_CreateProveJob_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateProveJobRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Groth16Server).CreateProveJob(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Groth16_CreateProveJob_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Groth16Server).CreateProveJob(ctx, req.(*CreateProveJobRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Groth16_CancelProveJob_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CancelProveJobRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Groth16Server).CancelProveJob(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Groth16_CancelProveJob_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Groth16Server).CancelProveJob(ctx, req.(*CancelProveJobRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Groth16_ListProveJob_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListProveJobRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Groth16Server).ListProveJob(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Groth16_ListProveJob_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Groth16Server).ListProveJob(ctx, req.(*ListProveJobRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Groth16_SubscribeToProveJob_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(SubscribeToProveJobRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(Groth16Server).SubscribeToProveJob(m, &grpc.GenericServerStream[SubscribeToProveJobRequest, ProveJobResult]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Groth16_SubscribeToProveJobServer = grpc.ServerStreamingServer[ProveJobResult]

// Groth16_ServiceDesc is the grpc.ServiceDesc for Groth16 service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Groth16_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "gnarkd.Groth16",
	HandlerType: (*Groth16Server)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Prove",
			Handler:    _Groth16_Prove_Handler,
		},
		{
			MethodName: "Verify",
			Handler:    _Groth16_Verify_Handler,
		},
		{
			MethodName: "CreateProveJob",
			Handler:    _Groth16_CreateProveJob_Handler,
		},
		{
			MethodName: "CancelProveJob",
			Handler:    _Groth16_CancelProveJob_Handler,
		},
		{
			MethodName: "ListProveJob",
			Handler:    _Groth16_ListProveJob_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SubscribeToProveJob",
			Handler:       _Groth16_SubscribeToProveJob_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "api/gnark.proto",
}
