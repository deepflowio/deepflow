package config

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"gitlab.x.lan/yunshan/droplet-libs/grpc"
	"gitlab.x.lan/yunshan/message/trident"
	"golang.org/x/net/context"
)

const (
	DEFAULT_SYNC_INTERVAL = 10 * time.Second
)

type RpcConfigSynchronizer struct {
	sync.Mutex
	grpc.GrpcSession

	bootTime     time.Time
	syncInterval time.Duration

	handlers       []Handler
	stop           bool
	configAccepted bool
	Version        uint64
}

func (s *RpcConfigSynchronizer) sync() error {
	var response *trident.SyncResponse
	err := s.GrpcSession.Request(func(ctx context.Context) error {
		var err error
		request := trident.SyncRequest{
			BootTime:       proto.Uint32(uint32(s.bootTime.Unix())),
			ConfigAccepted: proto.Bool(s.configAccepted),
			Version:        proto.Uint64(s.Version),
		}
		client := trident.NewSynchronizerClient(s.GrpcSession.GetClient())
		response, err = client.Sync(ctx, &request)
		return err
	})
	if err != nil {
		return err
	}
	if status := response.GetStatus(); status != trident.Status_SUCCESS {
		return errors.New("Status Unsuccessful")
	}
	s.syncInterval = time.Duration(response.GetConfig().GetSyncInterval()) * time.Second
	s.Lock()
	for _, handler := range s.handlers {
		handler(response)
	}
	s.Unlock()
	s.Version = response.GetVersion()
	return nil
}

func (s *RpcConfigSynchronizer) Register(handler Handler) {
	s.Lock()
	s.handlers = append(s.handlers, handler)
	s.Unlock()
}

func NewRpcConfigSynchronizer(ips []net.IP, port uint16, timeout time.Duration) ConfigSynchronizer {
	s := &RpcConfigSynchronizer{
		GrpcSession:    grpc.GrpcSession{},
		bootTime:       time.Now(),
		configAccepted: true,
	}
	runOnce := func() {
		if err := s.sync(); err != nil {
			log.Warning(err)
			return
		}
	}
	s.GrpcSession.Init(ips, port, DEFAULT_SYNC_INTERVAL, runOnce)
	s.GrpcSession.SetTimeout(timeout)
	return s
}
