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

package decoder

import (
	"fmt"
	"net"

	"github.com/gogo/protobuf/proto"
	"golang.org/x/net/context"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/grpc"
)

func (p *ResourceInfoTable) QueryResourceInfo(resourceType uint32, resourceID uint32) *ResourceInfo {
	switch trident.DeviceType(resourceType) {
	case trident.DeviceType_DEVICE_TYPE_POD:
		return p.podInfos[resourceID]
	case trident.DeviceType_DEVICE_TYPE_POD_NODE:
		return p.podNodeInfos[resourceID]
	case trident.DeviceType_DEVICE_TYPE_HOST_DEVICE:
		return p.hostInfos[resourceID]
	default:
		return p.resourceInfos[uint64(resourceType)<<32|uint64(resourceID)]
	}

}

func (p *ResourceInfoTable) Close() {
	p.GrpcSession.Close()
}

func (p *ResourceInfoTable) Start() {
	p.GrpcSession.Start()
}

type ResourceInfo struct {
	L3EpcID      int32
	HostID       uint32
	RegionID     uint32
	L3DeviceType uint32
	L3DeviceID   uint32
	PodNodeID    uint32
	PodNSID      uint32
	PodGroupID   uint32
	PodGroupType uint8 // no need to store
	PodID        uint32
	PodClusterID uint32
	AZID         uint32
}

type ResourceInfoTable struct {
	ctlIP               string
	GrpcSession         *grpc.GrpcSession
	versionPlatformData uint64

	resourceInfos map[uint64]*ResourceInfo
	podInfos      map[uint32]*ResourceInfo
	podNodeInfos  map[uint32]*ResourceInfo
	hostInfos     map[uint32]*ResourceInfo
}

func NewResourceInfoTable(ips []net.IP, port, rpcMaxMsgSize int) *ResourceInfoTable {
	info := &ResourceInfoTable{
		GrpcSession:   &grpc.GrpcSession{},
		resourceInfos: make(map[uint64]*ResourceInfo),
		podInfos:      make(map[uint32]*ResourceInfo),
		podNodeInfos:  make(map[uint32]*ResourceInfo),
		hostInfos:     make(map[uint32]*ResourceInfo),
	}
	runOnce := func() {
		if err := info.Reload(); err != nil {
			log.Warning(err)
		}
	}
	info.GrpcSession.Init(ips, uint16(port), grpc.DEFAULT_SYNC_INTERVAL, rpcMaxMsgSize, runOnce)
	info.Reload()
	log.Infof("New ResourceInfoTable ips:%v port:%d rpcMaxMsgSize:%d", ips, port, rpcMaxMsgSize)
	return info
}

func (p *ResourceInfoTable) Reload() error {
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
			VersionPlatformData: proto.Uint64(p.versionPlatformData),
			CtrlIp:              proto.String(p.ctlIP),
			ProcessName:         proto.String("resource-info-watcher"),
		}
		c := p.GrpcSession.GetClient()
		if c == nil {
			return fmt.Errorf("can't get grpc client to %s", remote)
		}
		client := trident.NewSynchronizerClient(c)
		response, err = client.AnalyzerSync(ctx, &request)
		return err
	})
	if err != nil {
		return err
	}

	if status := response.GetStatus(); status != trident.Status_SUCCESS {
		return fmt.Errorf("grpc resource  response failed. responseStatus is %v", status)
	}

	newVersion := response.GetVersionPlatformData()
	if newVersion == p.versionPlatformData {
		return nil
	}

	platformData := trident.PlatformData{}
	if plarformCompressed := response.GetPlatformData(); plarformCompressed != nil {
		if err := platformData.Unmarshal(plarformCompressed); err != nil {
			log.Warningf("unmarshal grpc compressed platformData failed as %v", err)
			return err
		}
	}

	resourceInfos := make(map[uint64]*ResourceInfo)
	podInfos := make(map[uint32]*ResourceInfo)
	podNodeInfos := make(map[uint32]*ResourceInfo)
	hostInfos := make(map[uint32]*ResourceInfo)
	for _, intf := range platformData.GetInterfaces() {
		updateResourceInfos(resourceInfos, podInfos, podNodeInfos, hostInfos, intf)
	}
	p.resourceInfos = resourceInfos
	p.podInfos = podInfos
	p.podNodeInfos = podNodeInfos
	p.hostInfos = hostInfos

	log.Infof("Event update rpc platformdata version %d -> %d", p.versionPlatformData, newVersion)

	return nil
}

func updateResourceInfos(reourceInfos map[uint64]*ResourceInfo, podInfos, podNodeInfos, hostInfos map[uint32]*ResourceInfo, intf *trident.Interface) {
	epcID := intf.GetEpcId()
	if epcID == 0 {
		tmp := datatype.EPC_FROM_DEEPFLOW
		epcID = uint32(tmp)
	}
	deviceType := intf.GetDeviceType()
	deviceID := intf.GetDeviceId()
	podID := intf.GetPodId()
	podNodeID := intf.GetPodNodeId()
	hostID := intf.GetLaunchServerId()

	info := &ResourceInfo{
		L3EpcID:      int32(epcID),
		HostID:       hostID,
		RegionID:     intf.GetRegionId(),
		L3DeviceType: deviceType,
		L3DeviceID:   deviceID,
		PodNodeID:    podNodeID,
		PodNSID:      intf.GetPodNsId(),
		PodGroupID:   intf.GetPodGroupId(),
		PodGroupType: uint8(intf.GetPodGroupType()),
		PodID:        podID,
		PodClusterID: intf.GetPodClusterId(),
		AZID:         intf.GetAzId(),
	}
	reourceInfos[uint64(deviceType)<<32|uint64(deviceID)] = info
	podInfos[podID] = info

	nodeInfo := *info
	nodeInfo.PodID = 0
	nodeInfo.PodNSID = 0
	nodeInfo.PodGroupID = 0
	nodeInfo.PodGroupType = 0
	nodeInfo.PodClusterID = 0
	podNodeInfos[podNodeID] = &nodeInfo

	hostInfo := *info
	hostInfo.PodNodeID = 0
	hostInfo.PodID = 0
	hostInfo.PodNSID = 0
	hostInfo.PodGroupID = 0
	nodeInfo.PodGroupType = 0
	hostInfo.PodClusterID = 0
	hostInfos[hostID] = &hostInfo
}
