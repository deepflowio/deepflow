package labeler

import (
	"fmt"

	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/dropletpb"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"gitlab.x.lan/yunshan/droplet/dropletctl"
	"gitlab.x.lan/yunshan/message/trident"
)

var log = logging.MustGetLogger("labeler")

type QueueType uint8

const (
	QUEUE_TYPE_FLOW QueueType = iota
	QUEUE_TYPE_PCAP
	QUEUE_TYPE_MAX
)

const (
	QUEUE_BATCH_SIZE = 4096
)

type LabelerManager struct {
	command

	policyTable *policy.PolicyTable
	readQueues  []queue.QueueReader
	appQueues   [QUEUE_TYPE_MAX][]queue.QueueWriter
	running     bool

	lookupKey         []datatype.LookupKey
	rawPlatformDatas  []*datatype.PlatformData
	rawPeerConnection []*datatype.PeerConnection
	rawIpGroupDatas   []*policy.IpGroupData
	rawPolicyData     []*policy.Acl

	platformVersion, aclVersion, groupVersion uint64
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

func NewLabelerManager(readQueues []queue.QueueReader, mapSize uint32, disable bool, ddbsDisable bool) *LabelerManager {
	id := policy.DDBS
	if ddbsDisable {
		id = policy.NORMAL
	}
	labeler := &LabelerManager{
		lookupKey:   make([]datatype.LookupKey, len(readQueues)),
		policyTable: policy.NewPolicyTable(len(readQueues), mapSize, disable, id),
		readQueues:  readQueues,
	}
	labeler.command.init(labeler)
	debug.Register(dropletctl.DROPLETCTL_LABELER, labeler)
	stats.RegisterCountable("labeler", labeler)
	return labeler
}

func (l *LabelerManager) GetCounter() interface{} {
	return l.policyTable.GetCounter()
}

func (l *LabelerManager) Closed() bool {
	return false // FIXME: never close?
}

func (l *LabelerManager) RegisterAppQueue(queueType QueueType, appQueues []queue.QueueWriter) {
	if len(appQueues) != len(l.readQueues) {
		panic(fmt.Sprintf("Queue count (type %d) %d is not equal to input queue count %d.", queueType, len(appQueues), len(l.readQueues)))
	}
	l.appQueues[queueType] = appQueues
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
			log.Infof("droplet grpc recv %d pieces of platform data", len(l.rawPlatformDatas))
			log.Infof("droplet grpc recv %d pieces of peer connection data", len(l.rawPeerConnection))
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
		log.Infof("droplet grpc version ip-groups: %d, interfaces and peer-connections: %d, flow-acls: %d",
			response.GetVersionGroups(), response.GetVersionPlatformData(), response.GetVersionAcls())
		l.policyTable.UpdateInterfaceDataAndIpGroupData(l.rawPlatformDatas, l.rawIpGroupDatas)
		l.policyTable.UpdatePeerConnection(l.rawPeerConnection)
		l.policyTable.UpdateAclData(l.rawPolicyData)
		l.policyTable.EnableAclData()
		log.Info("droplet grpc enable fast-path policy change")
		log.Info("droplet grpc finish data change")
	}
}

func (l *LabelerManager) GetPolicy(packet *datatype.MetaPacket, index int) *datatype.PolicyData {
	key := &l.lookupKey[index]

	key.Timestamp = packet.Timestamp
	key.SrcMac = uint64(packet.MacSrc)
	key.DstMac = uint64(packet.MacDst)
	key.SrcIp = uint32(packet.IpSrc)
	key.DstIp = uint32(packet.IpDst)
	key.SrcPort = packet.PortSrc
	key.DstPort = packet.PortDst
	key.EthType = packet.EthType
	key.Vlan = packet.Vlan
	key.Proto = uint8(packet.Protocol)
	key.L2End0 = packet.L2End0
	key.L2End1 = packet.L2End1
	key.L3End0 = packet.L3End0
	key.L3End1 = packet.L3End1
	key.Tap = datatype.GetTapType(packet.InPort)
	key.Invalid = packet.Invalid
	key.FastIndex = index
	key.FeatureFlag = datatype.NPM
	key.Src6Ip = packet.Ip6Src
	key.Dst6Ip = packet.Ip6Dst

	packet.EndpointData, packet.PolicyData = l.policyTable.LookupAllByKey(key)
	return packet.PolicyData
}

func (l *LabelerManager) run(index int) {
	readQueue := l.readQueues[index]
	flowQueue := l.appQueues[QUEUE_TYPE_FLOW][index]
	captureQueue := l.appQueues[QUEUE_TYPE_PCAP][index]

	itemBatch := make([]interface{}, QUEUE_BATCH_SIZE)
	flowItemBatch := make([]interface{}, 0, QUEUE_BATCH_SIZE)
	captureItemBatch := make([]interface{}, 0, QUEUE_BATCH_SIZE)

	for l.running {
		itemCount := readQueue.Gets(itemBatch)
		for i, item := range itemBatch[:itemCount] {
			block := item.(*datatype.MetaPacketBlock)
			for i := uint8(0); i < block.Count; i++ {
				metaPacket := &block.Metas[i]
				action := l.GetPolicy(metaPacket, index)
				block.ActionFlags |= action.ActionFlags
			}
			if block.ActionFlags == 0 {
				datatype.ReleaseMetaPacketBlock(block)
				itemBatch[i] = nil
				continue
			}

			if block.ActionFlags&datatype.ACTION_PACKET_CAPTURING != 0 {
				block.AddReferenceCount()
				captureItemBatch = append(captureItemBatch, block)
			}

			if block.ActionFlags != datatype.ACTION_PACKET_CAPTURING { // 包统计、流统计、流存储
				block.AddReferenceCount()
				flowItemBatch = append(flowItemBatch, block)
			}

			datatype.ReleaseMetaPacketBlock(block)
			itemBatch[i] = nil
		}
		if len(flowItemBatch) > 0 {
			flowQueue.Put(flowItemBatch...)
			flowItemBatch = flowItemBatch[:0]
		}
		if len(captureItemBatch) > 0 {
			captureQueue.Put(captureItemBatch...)
			captureItemBatch = captureItemBatch[:0]
		}
	}

	log.Info("Labeler manager exit")
}

func (l *LabelerManager) Start() {
	if !l.running {
		l.running = true
		log.Info("Start labeler manager")
		for i := 0; i < len(l.readQueues); i++ {
			go l.run(i)
		}
	}
}

func (l *LabelerManager) Stop(wait bool) {
	if l.running {
		log.Info("Stop labeler manager")
		l.running = false
	}
}
