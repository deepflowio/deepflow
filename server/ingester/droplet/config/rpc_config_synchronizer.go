/*
 * Copyright (c) 2022 Yunshan Networks
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

package config

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/libs/grpc"
)

const (
	DEFAULT_SYNC_INTERVAL = 10 * time.Second
	DEFAULT_PUSH_INTERVAL = 2 * time.Second
)

type RpcInfoVersions struct {
	VersionPlatformData uint64
	VersionAcls         uint64
	VersionGroups       uint64
}

type RpcConfigSynchronizer struct {
	sync.Mutex
	PollingSession   grpc.GrpcSession
	triggeredSession grpc.GrpcSession

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

func (s *RpcConfigSynchronizer) pull() error {
	var stream trident.Synchronizer_PushClient
	var response *trident.SyncResponse
	err := s.triggeredSession.Request(func(ctx context.Context, _ net.IP) error {
		var err error
		request := trident.SyncRequest{
			BootTime:            proto.Uint32(uint32(s.bootTime.Unix())),
			ConfigAccepted:      proto.Bool(s.configAccepted),
			VersionPlatformData: proto.Uint64(s.VersionPlatformData),
			VersionAcls:         proto.Uint64(s.VersionAcls),
			VersionGroups:       proto.Uint64(s.VersionGroups),
			ProcessName:         proto.String("droplet"),
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
			handler(response, &s.RpcInfoVersions)
		}
		// 因为droplet停止后，trisolaris中对应的版本号不会清除，重启droplet后，trisolaris push
		// 下发的数据仅有版本号没有实际数据，所以策略和平台数据的初始化必须是由droplet主动请求
		// 的, sync使用版本号为0的请求会更新trisolaris中对应的版本
		if len(s.handlers) > 0 &&
			s.RpcInfoVersions.VersionPlatformData+s.RpcInfoVersions.VersionAcls+s.RpcInfoVersions.VersionGroups > 0 {
			s.updateVersions(response)
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
	s.PollingSession.Close()
	s.triggeredSession.Close()
}

func NewRpcConfigSynchronizer(ips []net.IP, port uint16, timeout time.Duration, maxMsgSize int) ConfigSynchronizer {
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
	s.PollingSession.Init(ips, port, DEFAULT_SYNC_INTERVAL, maxMsgSize, runOnce)
	s.PollingSession.SetTimeout(timeout)
	run := func() {
		if err := s.pull(); err != nil {
			log.Warning(err)
			return
		}
	}
	s.triggeredSession.Init(ips, port, DEFAULT_PUSH_INTERVAL, maxMsgSize, run)
	return s
}
