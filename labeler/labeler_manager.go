package labeler

import (
	"reflect"

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

type LabelerManager struct {
	command

	policyTable     *policy.PolicyTable
	readQueues      queue.MultiQueueReader
	readQueuesCount int
	appQueues       [QUEUE_TYPE_MAX]queue.MultiQueueWriter
	running         bool

	lookupKey         []datatype.LookupKey
	rawPlatformDatas  []*datatype.PlatformData
	rawIpGroupDatas   []*policy.IpGroupData
	rawPeerConnection []*datatype.PeerConnection
	rawPolicyData     []*policy.Acl
	enable            bool
	version           uint64
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

func NewLabelerManager(readQueues queue.MultiQueueReader, count int, size uint32, disable bool, ddbsDisable bool) *LabelerManager {
	id := policy.DDBS
	if ddbsDisable {
		id = policy.NORMAL
	}
	labeler := &LabelerManager{
		lookupKey:       make([]datatype.LookupKey, size),
		policyTable:     policy.NewPolicyTable(count, size, disable, id),
		readQueues:      readQueues,
		readQueuesCount: count,
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

func (l *LabelerManager) RegisterAppQueue(queueType QueueType, appQueues queue.MultiQueueWriter) {
	l.appQueues[queueType] = appQueues
}

func (l *LabelerManager) OnAclDataChange(response *trident.SyncResponse) {
	newVersion := response.GetVersion()
	log.Debugf("droplet grpc recv response with version %d, and current version is %d:", newVersion, l.version)
	if newVersion <= l.version {
		return
	}
	log.Infof("droplet grpc recv response with version %d (vs. current %d)", newVersion, l.version)

	if platformData := response.GetPlatformData(); platformData != nil {
		if interfaces := platformData.GetInterfaces(); interfaces != nil {
			platformData := dropletpb.Convert2PlatformData(interfaces)
			log.Infof("droplet grpc recv %d pieces of platform data", len(platformData))
			l.OnPlatformDataChange(platformData)
		} else {
			l.OnPlatformDataChange(nil)
		}
		if ipGroups := platformData.GetIpGroups(); ipGroups != nil {
			ipGroupData := dropletpb.Convert2IpGroupData(ipGroups)
			log.Infof("droplet grpc recv %d pieces of ipgroup data", len(ipGroupData))
			l.OnIpGroupDataChange(ipGroupData)
		} else {
			l.OnIpGroupDataChange(nil)
		}
		if peerConnections := platformData.GetPeerConnections(); peerConnections != nil {
			peerConnectionData := dropletpb.Convert2PeerConnections(peerConnections)
			log.Infof("droplet grpc recv %d pieces of peer connection data", len(peerConnectionData))
			l.OnPeerConnectionChange(peerConnectionData)
		} else {
			l.OnPeerConnectionChange(nil)
		}

	} else {
		l.OnPlatformDataChange(nil)
		l.OnIpGroupDataChange(nil)
		l.OnPeerConnectionChange(nil)
	}

	if flowAcls := response.GetFlowAcls(); flowAcls != nil {
		acls := dropletpb.Convert2AclData(flowAcls)
		log.Infof("droplet grpc recv %d pieces of acl data", len(acls))
		l.OnPolicyDataChange(acls)
	} else {
		l.OnPolicyDataChange(nil)
	}

	if l.enable {
		log.Info("droplet grpc enable fast-path policy change")
		l.policyTable.EnableAclData()
		l.enable = false
	}

	l.version = newVersion
	log.Info("droplet grpc finish data change")
}

func (l *LabelerManager) OnPlatformDataChange(data []*datatype.PlatformData) {
	if reflect.DeepEqual(l.rawPlatformDatas, data) {
		return
	}
	l.policyTable.UpdateInterfaceData(data)
	l.rawPlatformDatas = data
	l.enable = true
}

func (l *LabelerManager) OnIpGroupDataChange(data []*policy.IpGroupData) {
	if reflect.DeepEqual(l.rawIpGroupDatas, data) {
		return
	}
	l.policyTable.UpdateIpGroupData(data)
	l.rawIpGroupDatas = data
	l.enable = true
}

func (l *LabelerManager) OnPeerConnectionChange(data []*datatype.PeerConnection) {
	if reflect.DeepEqual(l.rawPeerConnection, data) {
		return
	}
	l.policyTable.UpdatePeerConnection(data)
	l.rawPeerConnection = data
	l.enable = true
}

func (l *LabelerManager) OnPolicyDataChange(data []*policy.Acl) {
	// DDBS算法中需要根据资源组查询MAC和IP建立查询表，
	// 所以当平台数据或IP资源组更新后，即使策略不变也应该重新建立查询表
	if reflect.DeepEqual(l.rawPolicyData, data) && !l.enable {
		return
	}
	l.policyTable.UpdateAclData(data)
	l.rawPolicyData = data
	l.enable = true
}

func getTTL(packet *datatype.MetaPacket) uint8 {
	if packet.InPort == datatype.PACKET_SOURCE_TOR {
		return 128
	}

	return packet.TTL
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
	key.Ttl = getTTL(packet)
	key.L2End0 = packet.L2End0
	key.L2End1 = packet.L2End1
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
	flowQueues := l.appQueues[QUEUE_TYPE_FLOW]
	captureQueues := l.appQueues[QUEUE_TYPE_PCAP]
	size := 1024 * 16
	userId := queue.HashKey(index)
	flowKeys := make([]queue.HashKey, 0, size+1)
	flowKeys = append(flowKeys, userId)
	captureKeys := make([]queue.HashKey, 0, size+1)
	captureKeys = append(captureKeys, userId)

	flowItemBatch := make([]interface{}, 0, size)
	captureItemBatch := make([]interface{}, 0, size)
	itemBatch := make([]interface{}, size)

	for l.running {
		itemCount := l.readQueues.Gets(userId, itemBatch)
		for i, item := range itemBatch[:itemCount] {
			metaPacket := item.(*datatype.MetaPacket)
			action := l.GetPolicy(metaPacket, index)

			if (action.ActionFlags & datatype.ACTION_PACKET_CAPTURING) != 0 {
				captureKeys = append(captureKeys, queue.HashKey(metaPacket.QueueHash))
				metaPacket.AddReferenceCount() // 引用计数+1，避免被释放
				captureItemBatch = append(captureItemBatch, metaPacket)
			}

			// 为了获取所以流量方向，所有流量都过flowgenerator
			flowKeys = append(flowKeys, queue.HashKey(metaPacket.QueueHash))
			flowItemBatch = append(flowItemBatch, metaPacket)

			itemBatch[i] = nil
		}
		if len(flowItemBatch) > 0 {
			flowQueues.Puts(flowKeys, flowItemBatch)
			flowKeys = flowKeys[:1]
			flowItemBatch = flowItemBatch[:0]
		}
		if len(captureItemBatch) > 0 {
			captureQueues.Puts(captureKeys, captureItemBatch)
			captureKeys = captureKeys[:1]
			captureItemBatch = captureItemBatch[:0]
		}
	}

	log.Info("Labeler manager exit")
}

func (l *LabelerManager) Start() {
	if !l.running {
		l.running = true
		log.Info("Start labeler manager")
		for i := 0; i < l.readQueuesCount; i++ {
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
