/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
	maxMsgSize   int
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
	// fix where multi thread run, may cause s.ipIndex++ >= s.ips and cause panic
	ipIndex := s.ipIndex + 1
	if ipIndex >= len(s.ips) {
		s.ipIndex = 0
		ipIndex = 0
	} else {
		s.ipIndex = ipIndex
	}
	server := fmt.Sprintf("%s:%d", s.ips[ipIndex], s.port)
	if s.ips[ipIndex].To4() == nil {
		server = fmt.Sprintf("[%s]:%d", s.ips[ipIndex], s.port)
	}
	options := make([]grpc.DialOption, 0, 4)
	options = append(options, grpc.WithInsecure(), grpc.WithTimeout(s.syncInterval),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(s.maxMsgSize)), grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(s.maxMsgSize)))
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
			if err := s.nextServer(); err != nil {
				return err
			}
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
	if s.stop {
		go s.run()
	}
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

func (s *GrpcSession) Init(ips []net.IP, port uint16, syncInterval time.Duration, maxMsgSize int, runOnce func()) {
	s.ips = ips
	s.port = port
	s.syncInterval = syncInterval
	s.maxMsgSize = maxMsgSize
	s.runOnce = runOnce
	s.ipIndex = -1
	s.synchronized = true // 避免启动后连接服务器失败时不打印
	s.stop = true
}
