package config

import (
	"errors"
	"io"
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
	DEFAULT_PUSH_INTERVAL = 2 * time.Second
)

type RpcConfigSynchronizer struct {
	sync.Mutex
	PollingSession   grpc.GrpcSession
	triggeredSession grpc.GrpcSession

	bootTime     time.Time
	syncInterval time.Duration

	handlers       []Handler
	stop           bool
	configAccepted bool
	Version        uint64
}

func (s *RpcConfigSynchronizer) sync() error {
	var response *trident.SyncResponse
	err := s.PollingSession.Request(func(ctx context.Context) error {
		var err error
		request := trident.SyncRequest{
			BootTime:       proto.Uint32(uint32(s.bootTime.Unix())),
			ConfigAccepted: proto.Bool(s.configAccepted),
			Version:        proto.Uint64(s.Version),
		}
		client := trident.NewSynchronizerClient(s.PollingSession.GetClient())
		response, err = client.Sync(ctx, &request)

		return err
	})
	if err != nil {
		return err
	}
	status := response.GetStatus()
	if status == trident.Status_HEARTBEAT {
		return nil
	}
	if status == trident.Status_FAILED {
		return errors.New("Status Unsuccessful")
	}
	s.syncInterval = time.Duration(response.GetConfig().GetSyncInterval()) * time.Second
	s.Lock()
	for _, handler := range s.handlers {
		handler(response)
	}
	if len(s.handlers) > 0 {
		s.Version = response.GetVersion()
	}
	s.Unlock()
	return nil
}

func (s *RpcConfigSynchronizer) pull() error {
	var stream trident.Synchronizer_PushClient
	var response *trident.SyncResponse
	err := s.triggeredSession.Request(func(ctx context.Context) error {
		var err error
		request := trident.SyncRequest{
			BootTime:       proto.Uint32(uint32(s.bootTime.Unix())),
			ConfigAccepted: proto.Bool(s.configAccepted),
			Version:        proto.Uint64(s.Version),
		}
		client := trident.NewSynchronizerClient(s.triggeredSession.GetClient())
		stream, err = client.Push(context.Background(), &request)
		return err
	})
	if err != nil {
		return err
	}
	for {
		response, err = stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		status := response.GetStatus()
		if status == trident.Status_HEARTBEAT {
			continue
		}
		if status == trident.Status_FAILED {
			log.Error("Status Unsuccessful")
			continue
		}
		s.Lock()
		for _, handler := range s.handlers {
			handler(response)
		}
		if len(s.handlers) > 0 {
			s.Version = response.GetVersion()
		}
		s.Unlock()
	}
	return nil
}

func (s *RpcConfigSynchronizer) Register(handler Handler) {
	s.Lock()
	s.handlers = append(s.handlers, handler)
	s.Unlock()
}

func (s *RpcConfigSynchronizer) Start() {
	s.PollingSession.Start()
	s.triggeredSession.Start()
}

func (s *RpcConfigSynchronizer) Stop() {
	s.PollingSession.Stop()
	s.triggeredSession.Stop()
}

func NewRpcConfigSynchronizer(ips []net.IP, port uint16, timeout time.Duration) ConfigSynchronizer {
	s := &RpcConfigSynchronizer{
		PollingSession:   grpc.GrpcSession{},
		triggeredSession: grpc.GrpcSession{},
		bootTime:         time.Now(),
		configAccepted:   true,
	}
	runOnce := func() {
		if err := s.sync(); err != nil {
			log.Warning(err)
			return
		}
	}
	s.PollingSession.Init(ips, port, DEFAULT_SYNC_INTERVAL, runOnce)
	s.PollingSession.SetTimeout(timeout)
	run := func() {
		if err := s.pull(); err != nil {
			log.Warning(err)
			return
		}
	}
	s.triggeredSession.Init(ips, port, DEFAULT_PUSH_INTERVAL, run)
	return s
}
