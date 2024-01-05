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

package labeler

import (
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/dropletpb"
	"github.com/deepflowio/deepflow/server/libs/policy"
	"github.com/deepflowio/deepflow/server/libs/queue"

	"github.com/deepflowio/deepflow/server/ingester/common"
	. "github.com/deepflowio/deepflow/server/ingester/droplet/common"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
)

var log = logging.MustGetLogger("labeler")

type LabelerManager struct {
	command

	policyTable *policy.PolicyTable

	lookupKey         []datatype.LookupKey
	rawPlatformDatas  []datatype.PlatformData
	rawPeerConnection []*datatype.PeerConnection
	rawCidrs          []*datatype.Cidr
	rawIpGroupDatas   []*policy.IpGroupData
	rawPolicyData     []*policy.Acl

	platformVersion, aclVersion, groupVersion uint64

	packetQueueReaders []queue.QueueReader
	packetQueueWriters []queue.QueueWriter

	PcapDataRetention time.Duration

	running bool
}

const (
	LABELER_CMD_DUMP_PLATFORM = iota
	LABELER_CMD_DUMP_ACL
	LABELER_CMD_DUMP_FIRST_ACL
	LABELER_CMD_DUMP_FAST_ACL
	LABELER_CMD_SHOW_ACL
	LABELER_CMD_ADD_ACL
	LABELER_CMD_DEL_ACL
	LABELER_CMD_SHOW_IPGROUP
)

type DumpKey struct {
	Mac    uint64
	Ip     uint32
	InPort uint32
}

func NewLabelerManager(packetQueueReaders []queue.QueueReader, packetQueueWriters []queue.QueueWriter, queueCount, level int, mapSize uint32, disable bool) *LabelerManager {
	labeler := &LabelerManager{
		packetQueueReaders: packetQueueReaders,
		packetQueueWriters: packetQueueWriters,
		lookupKey:          make([]datatype.LookupKey, queueCount),
		policyTable:        policy.NewPolicyTable(queueCount, level, mapSize, disable),
	}
	labeler.command.init(labeler)
	debug.Register(ingesterctl.INGESTERCTL_LABELER, labeler)
	common.RegisterCountableForIngester("labeler", labeler)
	return labeler
}

func (l *LabelerManager) GetCounter() interface{} {
	return l.policyTable.GetCounter()
}

func (l *LabelerManager) Closed() bool {
	return false // FIXME: never close?
}

func (l *LabelerManager) OnAclDataChange(response *trident.SyncResponse) {
	update := false
	newVersion := response.GetVersionPlatformData()
	log.Debugf("droplet grpc recv response with platform version %d, and current version is %d:", newVersion, l.platformVersion)
	if newVersion != l.platformVersion {
		log.Infof("droplet grpc recv response with platform version %d (vs. current %d)", newVersion, l.platformVersion)
		platformData := trident.PlatformData{}
		if err := platformData.Unmarshal(response.GetPlatformData()); err == nil {
			l.rawPlatformDatas = dropletpb.Convert2PlatformData(platformData.GetInterfaces())
			l.rawPeerConnection = dropletpb.Convert2PeerConnections(platformData.GetPeerConnections())
			l.rawCidrs = dropletpb.Convert2Cidrs(platformData.GetCidrs())
			log.Infof("droplet grpc recv %d pieces of platform data", len(l.rawPlatformDatas))
			log.Infof("droplet grpc recv %d pieces of peer connection data", len(l.rawPeerConnection))
			log.Infof("droplet grpc recv %d pieces of cidr data", len(l.rawCidrs))
			update = true
		}
		l.platformVersion = newVersion
	}

	newVersion = response.GetVersionGroups()
	log.Debugf("droplet grpc recv response with ip group version %d, and current version is %d:", newVersion, l.groupVersion)
	if newVersion != l.groupVersion {
		log.Infof("droplet grpc recv response with ip group version %d (vs. current %d)", newVersion, l.groupVersion)
		group := trident.Groups{}
		if err := group.Unmarshal(response.GetGroups()); err == nil {
			l.rawIpGroupDatas = dropletpb.Convert2IpGroupData(group.GetGroups())
			log.Infof("droplet grpc recv %d pieces of ipgroup data", len(l.rawIpGroupDatas))
			update = true
			// XXX: 目前性能分析、回溯取证已不再关心具体的GroupID，暂时屏蔽。一段时间后可彻底清除
			for _, g := range l.rawIpGroupDatas {
				g.Type = policy.ANONYMOUS
			}
		}
		l.groupVersion = newVersion
	}

	newVersion = response.GetVersionAcls()
	log.Debugf("droplet grpc recv response with acl version %d, and current version is %d:", newVersion, l.aclVersion)
	if newVersion != l.aclVersion {
		log.Infof("droplet grpc recv response with acl version %d (vs. current %d)", newVersion, l.aclVersion)
		acls := trident.FlowAcls{}
		if err := acls.Unmarshal(response.GetFlowAcls()); err == nil {
			l.rawPolicyData = dropletpb.Convert2AclData(acls.GetFlowAcl())
			log.Infof("droplet grpc recv %d pieces of acl data", len(l.rawPolicyData))
			update = true
		}
		l.aclVersion = newVersion
	}

	if update {
		log.Infof("droplet grpc version ip-groups: %d, interfaces peer-connections and cidrs: %d, flow-acls: %d",
			response.GetVersionGroups(), response.GetVersionPlatformData(), response.GetVersionAcls())
		l.policyTable.UpdateInterfaceData(l.rawPlatformDatas)
		l.policyTable.UpdateIpGroupData(l.rawIpGroupDatas)
		l.policyTable.UpdatePeerConnection(l.rawPeerConnection)
		l.policyTable.UpdateCidrs(l.rawCidrs)
		l.policyTable.UpdateAclData(l.rawPolicyData)
		l.policyTable.EnableAclData()
		log.Info("droplet grpc enable fast-path policy change")
		log.Info("droplet grpc finish data change")
	}
}

func (l *LabelerManager) GetPolicy(packet *datatype.MetaPacket, index int) {
	key := &l.lookupKey[index]

	key.Timestamp = packet.Timestamp
	key.SrcMac = uint64(packet.MacSrc)
	key.DstMac = uint64(packet.MacDst)
	key.SrcIp = uint32(packet.IpSrc)
	key.DstIp = uint32(packet.IpDst)
	key.SrcPort = packet.PortSrc
	key.DstPort = packet.PortDst
	key.EthType = packet.EthType
	key.Proto = uint8(packet.Protocol)
	key.L2End0 = packet.L2End0
	key.L2End1 = packet.L2End1
	key.L3End0 = packet.L3End0
	key.L3End1 = packet.L3End1
	key.L3EpcId0 = packet.L3EpcId0
	key.L3EpcId1 = packet.L3EpcId1
	key.TapType = packet.TapType
	key.FastIndex = index
	key.FeatureFlag = datatype.NPM
	key.Src6Ip = packet.Ip6Src
	key.Dst6Ip = packet.Ip6Dst

	l.policyTable.LookupAllByKey(key, &packet.PolicyData, &packet.EndpointData)
}

func (l *LabelerManager) run(id int) {
	in := l.packetQueueReaders[id]
	out := l.packetQueueWriters[id]
	elements := make([]interface{}, QUEUE_BATCH_SIZE)

	for l.running {
		n := in.Gets(elements)
		for _, e := range elements[:n] {
			block := e.(*datatype.MetaPacketBlock)
			for i := uint8(0); i < block.Count; i++ {
				packet := &block.Metas[i]
				l.GetPolicy(packet, id)
			}
			out.Put(block)
		}
	}
}

func (l *LabelerManager) Start() {
	if !l.running {
		l.running = true
		for i := 0; i < len(l.packetQueueReaders); i++ {
			go l.run(i)
		}
		log.Info("Start labeler manager")
	}
}

func (l *LabelerManager) Stop(wait bool) {
	if l.running {
		log.Info("Stop labeler manager")
		l.running = false
	}
}
