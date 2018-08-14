package config

import (
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"

	"gitlab.x.lan/yunshan/droplet/protobuf"
)

const (
	NORMAL_EXIT_WITH_RESTART  = 2
	DEFAULT_SYN_INTERVAL_TIME = 10
)

type RpcConfigSynchronizer struct {
	sync.Mutex

	bootTime     time.Time
	rpcSession   RpcSession
	syncInterval time.Duration

	handlers       []Handler
	stop           bool
	configAccepted bool
}

func (s *RpcConfigSynchronizer) request() (*protobuf.SyncResponse, error) {
	request := protobuf.SyncRequest{
		BootTime:       proto.Uint32(uint32(s.bootTime.Unix())),
		ConfigAccepted: proto.Bool(s.configAccepted),
	}
	return s.rpcSession.Request(&request)
}

func (s *RpcConfigSynchronizer) onResponse(response *protobuf.SyncResponse) {
	if status := response.GetStatus(); status != protobuf.Status_SUCCESS {
		log.Warning("Unsuccessful status:", response)
		return
	}
	s.syncInterval = time.Duration(response.GetConfig().GetSyncInterval()) * time.Second
	s.Lock()
	for _, handler := range s.handlers {
		handler(response)
	}
	s.Unlock()
}

func (s *RpcConfigSynchronizer) runOnce() {
	response, err := s.request()
	if err != nil {
		log.Warning(err)
		return
	}
	s.onResponse(response)
}

func (s *RpcConfigSynchronizer) run() {
	s.stop = false
	for !s.stop {
		s.runOnce()
		time.Sleep(s.syncInterval)
	}
	s.rpcSession.Close()
}

func (s *RpcConfigSynchronizer) Register(handler Handler) {
	s.Lock()
	s.handlers = append(s.handlers, handler)
	s.Unlock()
}

func (s *RpcConfigSynchronizer) Start() {
	go s.run()
}

func (s *RpcConfigSynchronizer) Stop() {
	s.stop = true
}

func NewRpcConfigSynchronizer(ips []net.IP, port uint16, syncInterval time.Duration) ConfigSynchronizer {
	return &RpcConfigSynchronizer{
		bootTime:       time.Now(),
		rpcSession:     NewGRpcInitiator(ips, port, syncInterval),
		syncInterval:   syncInterval,
		configAccepted: true,
	}
}
