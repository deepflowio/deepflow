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

package config

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/gogo/protobuf/proto"
	"golang.org/x/net/context"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/libs/grpc"
)

const SYNC_INTERVAL_FAST = 5 * time.Second // When the system first starts, increase the request frequency and obtain Node/Pod information as soon as possible.

func (p *ServerInstanceInfo) Close() {
	p.GrpcSession.Close()
}

func (p *ServerInstanceInfo) Start() {
	p.GrpcSession.Start()
}

func (p *ServerInstanceInfo) GetServerPodNames() []string {
	podNames := []string{}
	for _, v := range p.instanceInfos {
		podNames = append(podNames, v.PodName)
	}
	sort.Slice(podNames, func(i, j int) bool {
		return podNames[i] < podNames[j]
	})
	return podNames
}

func (p *ServerInstanceInfo) GetNodePodNames() map[string][]string {
	nodePodNames := make(map[string][]string)
	for _, v := range p.instanceInfos {
		podName := v.PodName
		nodeName := v.NodeName
		nodePodNames[nodeName] = append(nodePodNames[nodeName], podName)
	}

	return nodePodNames
}

type InstanceInfo struct {
	PodName  string
	NodeName string
}

type ServerInstanceInfo struct {
	ctlIP       string
	GrpcSession *grpc.GrpcSession

	instanceInfos []InstanceInfo

	firstGetInstanceTime int64
}

func NewServerInstranceInfo(ips []net.IP, port, rpcMaxMsgSize int) *ServerInstanceInfo {
	info := &ServerInstanceInfo{
		GrpcSession: &grpc.GrpcSession{},
	}
	runOnce := func() {
		if err := info.Reload(); err != nil {
			log.Warning(err)
		}
	}
	info.GrpcSession.Init(ips, uint16(port), SYNC_INTERVAL_FAST, rpcMaxMsgSize, runOnce)
	info.Reload()
	log.Infof("New ServerInstranceInfo ips:%v port:%d rpcMaxMsgSize:%d", ips, port, rpcMaxMsgSize)
	info.GrpcSession.Start()
	return info
}

func (p *ServerInstanceInfo) Reload() error {
	var response *trident.SyncResponse
	err := p.GrpcSession.Request(func(ctx context.Context, remote net.IP) error {
		var err error
		if p.ctlIP == "" {
			var local net.IP
			// 根据remote ip获取本端ip
			if local, err = grpc.Lookup(remote); err != nil {
				return err
			}
			p.ctlIP = local.String()
		}

		request := trident.SyncRequest{
			CtrlIp:      proto.String(p.ctlIP),
			ProcessName: proto.String("server-pod-names-watcher"),
		}
		client := trident.NewSynchronizerClient(p.GrpcSession.GetClient())
		response, err = client.AnalyzerSync(ctx, &request)
		return err
	})
	if err != nil {
		return err
	}

	if status := response.GetStatus(); status != trident.Status_SUCCESS {
		return fmt.Errorf("grpc response failed. responseStatus is %v", status)
	}

	serverInstanceInfos := response.GetDeepflowServerInstances()
	instanceInfos := []InstanceInfo{}
	for _, v := range serverInstanceInfos {
		instanceInfos = append(instanceInfos, InstanceInfo{
			PodName:  *v.PodName,
			NodeName: *v.NodeName,
		})
	}

	if len(instanceInfos) != 0 && p.firstGetInstanceTime == 0 {
		p.firstGetInstanceTime = time.Now().UnixNano()
		log.Infof("get instance info: %+v", instanceInfos)
	}

	// 1 minute after the data is obtained, the request frequency is reduced to once per minute
	if p.firstGetInstanceTime > 0 && time.Now().UnixNano()-p.firstGetInstanceTime > int64(time.Minute) {
		p.GrpcSession.SetSyncInterval(grpc.DEFAULT_SYNC_TIMEOUT)
	}

	p.instanceInfos = instanceInfos

	return nil
}
