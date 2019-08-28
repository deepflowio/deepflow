package labeler

import (
	"fmt"
	"reflect"

	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/dropletpb"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"gitlab.x.lan/yunshan/droplet/config"
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

func (l *LabelerManager) CheckAndUpdatePlatformData(response *trident.SyncResponse, version uint64) {
	VersionPlatformData := response.GetVersionPlatformData()
	log.Debugf("grpc recv platformData with version %d, and current version is %d:",
		VersionPlatformData, version)
	if VersionPlatformData <= version {
		return
	}
	log.Infof("droplet grpc recv platformData with version %d (vs. current %d)", VersionPlatformData, version)

	platformData := trident.PlatformData{}
	if plarformCompressed := response.GetPlatformData(); plarformCompressed != nil {
		if err := platformData.XXX_Unmarshal(plarformCompressed); err != nil {
			log.Warningf("unmarshal grpc compressed platformData failed as %v", err)
			return
		}
		if interfaces := platformData.GetInterfaces(); interfaces != nil {
			platformData := dropletpb.Convert2PlatformData(interfaces)
			log.Infof("droplet grpc recv %d pieces of platform data", len(platformData))
			l.OnPlatformDataChange(platformData)
		} else {
			l.OnPlatformDataChange(nil)
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
		l.OnPeerConnectionChange(nil)
	}
}

func (l *LabelerManager) CheckAndUpdateGroups(response *trident.SyncResponse, version uint64) {
	VersionGroups := response.GetVersionGroups()
	log.Debugf("grpc recv groups with version %d, and current version is %d:",
		VersionGroups, version)
	if VersionGroups <= version {
		return
	}
	log.Infof("droplet grpc recv groups with version %d (vs. current %d)", VersionGroups, version)

	groups := trident.Groups{}
	if groupsCompressed := response.GetGroups(); groupsCompressed != nil {
		if err := groups.XXX_Unmarshal(groupsCompressed); err != nil {
			log.Warningf("unmarshal grpc compressed groups failed as %v", err)
			return
		}
		if group := groups.GetGroups(); group != nil {
			ipGroupData := dropletpb.Convert2IpGroupData(group)
			log.Infof("droplet grpc recv %d pieces of ipgroup data", len(ipGroupData))
			l.OnIpGroupDataChange(ipGroupData)
		} else {
			l.OnIpGroupDataChange(nil)
		}

	} else {
		l.OnIpGroupDataChange(nil)
	}
}

func (l *LabelerManager) CheckAndUpdateFlowAcls(response *trident.SyncResponse, version uint64) {
	versionFlowAcls := response.GetVersionAcls()
	log.Debugf("grpc recv flowAcls with version %d, and current version is %d:",
		versionFlowAcls, version)
	if versionFlowAcls <= version {
		return
	}
	log.Infof("droplet grpc recv flowAcls with version %d (vs. current %d)", versionFlowAcls, version)

	flowAcls := trident.FlowAcls{}
	if flowAclsCompressed := response.GetFlowAcls(); flowAclsCompressed != nil {
		if err := flowAcls.XXX_Unmarshal(flowAclsCompressed); err != nil {
			return
		}
		if flowAcl := flowAcls.GetFlowAcl(); flowAcl != nil {
			acls := dropletpb.Convert2AclData(flowAcl)
			log.Infof("droplet grpc recv %d pieces of acl data", len(acls))
			l.OnPolicyDataChange(acls)
		} else {
			l.OnPolicyDataChange(nil)
		}
	} else {
		l.OnPolicyDataChange(nil)
	}

	if l.enable {
		log.Info("droplet grpc enable fast-path policy change")
		l.policyTable.EnableAclData()
		l.enable = false
	}
}

func (l *LabelerManager) OnAclDataChange(response *trident.SyncResponse, version *config.RpcInfoVersions) {
	l.CheckAndUpdatePlatformData(response, version.VersionPlatformData)
	l.CheckAndUpdateGroups(response, version.VersionGroups)
	l.CheckAndUpdateFlowAcls(response, version.VersionAcls)

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
	readQueue := l.readQueues[index]
	flowQueue := l.appQueues[QUEUE_TYPE_FLOW][index]
	captureQueue := l.appQueues[QUEUE_TYPE_PCAP][index]

	itemBatch := make([]interface{}, QUEUE_BATCH_SIZE)
	flowItemBatch := make([]interface{}, 0, QUEUE_BATCH_SIZE)
	captureItemBatch := make([]interface{}, 0, QUEUE_BATCH_SIZE)

	for l.running {
		itemCount := readQueue.Gets(itemBatch)
		for i, item := range itemBatch[:itemCount] {
			metaPacket := item.(*datatype.MetaPacket)
			action := l.GetPolicy(metaPacket, index)
			if action.ActionFlags == 0 {
				datatype.ReleaseMetaPacket(metaPacket)
				itemBatch[i] = nil
				continue
			}

			if action.ActionFlags&datatype.ACTION_PACKET_CAPTURING != 0 {
				if action.ActionFlags != datatype.ACTION_PACKET_CAPTURING {
					metaPacket.AddReferenceCount() // 引用计数+1，避免被释放
				}
				captureItemBatch = append(captureItemBatch, metaPacket)
			}

			if action.ActionFlags != datatype.ACTION_PACKET_CAPTURING {
				// 为了获取所以流量方向，所有流量都过flowgenerator
				flowItemBatch = append(flowItemBatch, metaPacket)
			}

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
