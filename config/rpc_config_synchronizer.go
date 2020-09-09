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
	DEFAULT_SYNC_INTERVAL = 2 * time.Second
)

type RpcInfoVersions struct {
	VersionPlatformData uint64
	VersionAcls         uint64
	VersionGroups       uint64
}

type RpcConfigSynchronizer struct {
	sync.Mutex
	PollingSession grpc.GrpcSession

	bootTime     time.Time
	syncInterval time.Duration

	handlers       []Handler
	stop           bool
	configAccepted bool
	RpcInfoVersions
}

func (s *RpcConfigSynchronizer) updateVersions(response *trident.SyncResponse) {
	s.RpcInfoVersions.VersionPlatformData = response.GetVersionPlatformData()
	s.RpcInfoVersions.VersionAcls = response.GetVersionAcls()
	s.RpcInfoVersions.VersionGroups = response.GetVersionGroups()
}

func (s *RpcConfigSynchronizer) sync() error {
	var response *trident.SyncResponse
	err := s.PollingSession.Request(func(ctx context.Context, _ net.IP) error {
		var err error
		request := trident.SyncRequest{
			BootTime:            proto.Uint32(uint32(s.bootTime.Unix())),
			ConfigAccepted:      proto.Bool(s.configAccepted),
			VersionPlatformData: proto.Uint64(s.VersionPlatformData),
			VersionAcls:         proto.Uint64(s.VersionAcls),
			VersionGroups:       proto.Uint64(s.VersionGroups),
			ProcessName:         proto.String("droplet"),
		}
		client := trident.NewSynchronizerClient(s.PollingSession.GetClient())
		response, err = client.AnalyzerSync(ctx, &request)

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
		handler(response, &s.RpcInfoVersions)
	}
	if len(s.handlers) > 0 {
		s.updateVersions(response)
	}
	s.Unlock()
	return nil
}

func (s *RpcConfigSynchronizer) Register(handler Handler) {
	s.Lock()
	s.handlers = append(s.handlers, handler)
	s.Unlock()
}

func (s *RpcConfigSynchronizer) Start() {
	s.PollingSession.Start()
}

func (s *RpcConfigSynchronizer) Stop() {
	s.PollingSession.Close()
}

func NewRpcConfigSynchronizer(ips []net.IP, port uint16, timeout time.Duration) ConfigSynchronizer {
	s := &RpcConfigSynchronizer{
		PollingSession: grpc.GrpcSession{},
		bootTime:       time.Now(),
		configAccepted: true,
	}
	runOnce := func() {
		if err := s.sync(); err != nil {
			log.Warning(err)
			return
		}
	}
	s.PollingSession.Init(ips, port, DEFAULT_SYNC_INTERVAL, runOnce)
	s.PollingSession.SetTimeout(timeout)
	return s
}
