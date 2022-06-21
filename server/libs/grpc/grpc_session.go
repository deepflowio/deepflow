package grpc

import (
	"errors"
	"fmt"
	"net"
	"time"

	logging "github.com/op/go-logging"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	DEFAULT_SYNC_TIMEOUT = 8 * time.Second
)

var log = logging.MustGetLogger("grpc")

type SyncFunction func(context.Context, net.IP) error

type GrpcSession struct {
	ips          []net.IP
	port         uint16
	syncInterval time.Duration
	runOnce      func()

	stop         bool
	ipIndex      int
	clientConn   *grpc.ClientConn
	synchronized bool
	timeout      time.Duration
}

func (s *GrpcSession) GetClient() *grpc.ClientConn {
	return s.clientConn
}

func (s *GrpcSession) SetSyncInterval(syncInterval time.Duration) {
	s.syncInterval = syncInterval
}

func (s *GrpcSession) nextServer() error {
	s.CloseConnection()
	s.ipIndex++
	if s.ipIndex >= len(s.ips) {
		s.ipIndex = 0
	}
	server := fmt.Sprintf("%s:%d", s.ips[s.ipIndex], s.port)
	if s.ips[s.ipIndex].To4() == nil {
		server = fmt.Sprintf("[%s]:%d", s.ips[s.ipIndex], s.port)
	}
	size := 1024 * 1024 * 20
	options := make([]grpc.DialOption, 0, 4)
	options = append(options, grpc.WithInsecure(), grpc.WithTimeout(s.syncInterval),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(size)), grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(size)))
	clientConn, err := grpc.Dial(server, options...)
	if err != nil {
		return err
	}
	s.clientConn = clientConn
	return nil
}

func (s *GrpcSession) Request(syncFunction SyncFunction) error {
	if s.clientConn == nil {
		if err := s.nextServer(); err != nil {
			return err
		}
	}
	timeout := DEFAULT_SYNC_TIMEOUT
	if s.timeout > 0 {
		timeout = s.timeout
	}
	for i := 0; i < len(s.ips); i++ {
		ctx, _ := context.WithTimeout(context.Background(), timeout)
		if err := syncFunction(ctx, s.ips[i]); err != nil {
			if s.synchronized {
				s.synchronized = false
				log.Warningf("Sync from server %s failed, reason: %s", s.ips[s.ipIndex], err.Error())
			}
			s.nextServer()
			continue
		}
		if !s.synchronized {
			s.synchronized = true
			log.Info("Synchronized to server", s.ips[s.ipIndex])
		}
		return nil
	}
	return errors.New("No reachable server")
}

func (s *GrpcSession) run() {
	s.stop = false
	for !s.stop {
		s.runOnce()
		time.Sleep(s.syncInterval)
	}
	s.CloseConnection()
}

func (s *GrpcSession) Start() {
	go s.run()
}

func (s *GrpcSession) Close() {
	s.stop = true
}

func (s *GrpcSession) CloseConnection() {
	if s.clientConn != nil {
		s.clientConn.Close()
		s.clientConn = nil
	}
}

func (s *GrpcSession) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

func (s *GrpcSession) Init(ips []net.IP, port uint16, syncInterval time.Duration, runOnce func()) {
	s.ips = ips
	s.port = port
	s.syncInterval = syncInterval
	s.runOnce = runOnce
	s.ipIndex = -1
	s.synchronized = true // 避免启动后连接服务器失败时不打印
}
