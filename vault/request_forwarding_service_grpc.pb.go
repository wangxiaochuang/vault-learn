package vault

import (
	context "context"

	forwarding "github.com/hashicorp/vault/helper/forwarding"
	grpc "google.golang.org/grpc"
)

// p21
type RequestForwardingClient interface {
	ForwardRequest(ctx context.Context, in *forwarding.Request, opts ...grpc.CallOption) (*forwarding.Response, error)
	Echo(ctx context.Context, in *EchoRequest, opts ...grpc.CallOption) (*EchoReply, error)
	PerformanceStandbyElectionRequest(ctx context.Context, in *PerfStandbyElectionInput, opts ...grpc.CallOption) (RequestForwarding_PerformanceStandbyElectionRequestClient, error)
}

// p68
type RequestForwarding_PerformanceStandbyElectionRequestClient interface {
	Recv() (*PerfStandbyElectionResponse, error)
	grpc.ClientStream
}
