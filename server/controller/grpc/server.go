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
	"context"
	"net"
	"sync"

	"github.com/op/go-logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/grpc/statsd"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

var log = logging.MustGetLogger("grpc/server")

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

func Run(ctx context.Context, cfg *config.ControllerConfig) {
	server := newServer(cfg.GrpcMaxMessageLength)
	for _, registration := range register.r {
		registration.Register(server)
	}

	addr := net.JoinHostPort("", cfg.GrpcPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("net.Listen err: %v", err)
	}
	statsd.Start()
	go server.Serve(lis)
	log.Infof("listening and serving GRPC on: %s", cfg.GrpcPort)

	wg := utils.GetWaitGroupInCtx(ctx)
	wg.Add(1)
	defer wg.Done()
	<-ctx.Done()
	server.Stop()
	log.Info("grpc server shutdown")
}

func newServer(maxMsgSize int, opts ...grpc.ServerOption) *grpc.Server {
	opts = append(opts, grpc.MaxMsgSize(maxMsgSize))
	opts = append(opts, grpc.MaxRecvMsgSize(maxMsgSize))
	opts = append(opts, grpc.MaxSendMsgSize(maxMsgSize))
	return grpc.NewServer(opts...)
}

func RunTLS(ctx context.Context, cfg *config.ControllerConfig) {
	creds, err := credentials.NewServerTLSFromFile(cfg.AgentSSLKeyFile, cfg.AgentSSLCertFile)
	if err != nil {
		log.Errorf("failed to generate credentials %v, key file: %s, cert file: %s", err, cfg.AgentSSLKeyFile, cfg.AgentSSLCertFile)
		return
	}
	sslServer := newServer(cfg.GrpcMaxMessageLength, grpc.Creds(creds))
	for _, registration := range register.r {
		registration.Register(sslServer)
	}

	addr := net.JoinHostPort("", cfg.SSLGrpcPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("ssl net.Listen err: %v", err)
		return
	}
	go sslServer.Serve(lis)
	log.Infof("listening and serving SSL GRPC on: %s", cfg.SSLGrpcPort)

	wg := utils.GetWaitGroupInCtx(ctx)
	wg.Add(1)
	defer wg.Done()
	<-ctx.Done()
	sslServer.Stop()
	log.Info("grpc ssl server shutdown")
}
