package healthcheck

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	grpcserver "github.com/metaflowys/metaflow/server/controller/trisolaris/server/grpc"
)

type service struct {
	serve *health.Server
}

func init() {
	grpcserver.Add(newService())
}

func newService() *service {
	healthServer := health.NewServer()
	healthServer.SetServingStatus("grpc.health.v1.Health", healthpb.HealthCheckResponse_SERVING)
	return &service{
		serve: healthServer,
	}
}

func (s *service) Register(gs *grpc.Server) error {
	healthpb.RegisterHealthServer(gs, s.serve)
	return nil
}
