package grpc

import (
	"context"
	"net"
	"sync"

	"github.com/op/go-logging"
	"google.golang.org/grpc"

	"github.com/metaflowys/metaflow/server/controller/trisolaris/config"
	"github.com/metaflowys/metaflow/server/controller/trisolaris/utils"
)

var log = logging.MustGetLogger("server")

var register = struct {
	sync.RWMutex
	r []Registration
}{}

type Registration interface {
	Register(*grpc.Server) error
}

func Add(r interface{}) {
	register.Lock()
	defer register.Unlock()

	register.r = append(register.r, (r).(Registration))
}

func Run(ctx context.Context, cfg *config.Config) {
	maxMsgSize := cfg.GrpcMaxMessageLength
	server := grpc.NewServer(
		grpc.MaxMsgSize(maxMsgSize),
		grpc.MaxRecvMsgSize(maxMsgSize),
		grpc.MaxSendMsgSize(maxMsgSize),
	)
	for _, registration := range register.r {
		registration.Register(server)
	}

	addr := net.JoinHostPort("", cfg.TridentPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("net.Listen err: %v", err)
	}

	go server.Serve(lis)

	wg := utils.GetWaitGroupInCtx(ctx)
	wg.Add(1)
	defer wg.Done()
	<-ctx.Done()
	log.Info("grpc server shutdown")
	server.GracefulStop()
}
