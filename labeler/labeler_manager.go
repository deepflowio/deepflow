package labeler

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"math"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/dropletpb"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"

	"gitlab.x.lan/yunshan/droplet/dropletctl"
	"gitlab.x.lan/yunshan/message/trident"
)

var log = logging.MustGetLogger("labeler")

type QueueType uint8

const (
	QUEUE_TYPE_FLOW QueueType = iota
	QUEUE_TYPE_METERING
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

	lookupKey        []datatype.LookupKey
	rawPlatformDatas []*datatype.PlatformData
	rawIpGroupDatas  []*policy.IpGroupData
	rawPolicyData    []*policy.Acl
	enable           bool
	version          uint64
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
		policyTable:     policy.NewPolicyTable(datatype.ACTION_FLOW_COUNTING, count, size, disable, id),
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
	} else {
		l.OnPlatformDataChange(nil)
		l.OnIpGroupDataChange(nil)
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
	meteringQueues := l.appQueues[QUEUE_TYPE_METERING]
	flowQueues := l.appQueues[QUEUE_TYPE_FLOW]
	captureQueues := l.appQueues[QUEUE_TYPE_PCAP]
	size := 1024 * 16
	userId := queue.HashKey(index)
	meteringKeys := make([]queue.HashKey, 0, size+1)
	meteringKeys = append(meteringKeys, userId)
	flowKeys := make([]queue.HashKey, 0, size+1)
	flowKeys = append(flowKeys, userId)
	captureKeys := make([]queue.HashKey, 0, size+1)
	captureKeys = append(captureKeys, userId)

	meteringItemBatch := make([]interface{}, 0, size)
	flowItemBatch := make([]interface{}, 0, size)
	captureItemBatch := make([]interface{}, 0, size)
	itemBatch := make([]interface{}, size)

	flowAppActions := datatype.ACTION_FLOW_COUNTING | datatype.ACTION_FLOW_STORING | datatype.ACTION_TCP_FLOW_PERF_COUNTING |
		datatype.ACTION_FLOW_MISC_COUNTING | datatype.ACTION_FLOW_COUNT_BROKERING | datatype.ACTION_TCP_FLOW_PERF_COUNT_BROKERING | datatype.ACTION_GEO_POSITIONING

	for l.running {
		itemCount := l.readQueues.Gets(userId, itemBatch)
		for i, item := range itemBatch[:itemCount] {
			metaPacket := item.(*datatype.MetaPacket)
			action := l.GetPolicy(metaPacket, index)

			if (action.ActionFlags & flowAppActions) != 0 {
				flowKeys = append(flowKeys, queue.HashKey(metaPacket.Hash))
				// droplet-ctl、meteringApp和flowApp均不会对metaPacket做修改
				metaPacket.AddReferenceCount() // 引用计数+1，避免被释放
				flowItemBatch = append(flowItemBatch, metaPacket)
			}

			if (action.ActionFlags & datatype.ACTION_PACKET_CAPTURING) != 0 {
				captureKeys = append(captureKeys, queue.HashKey(metaPacket.Hash))
				metaPacket.AddReferenceCount() // 引用计数+1，避免被释放
				captureItemBatch = append(captureItemBatch, metaPacket)
			}

			// 为了统计平台处理的总流量，所有流量都过meteringApp
			meteringKeys = append(meteringKeys, queue.HashKey(metaPacket.Hash))
			meteringItemBatch = append(meteringItemBatch, metaPacket)

			itemBatch[i] = nil
		}
		if len(meteringItemBatch) > 0 {
			meteringQueues.Puts(meteringKeys, meteringItemBatch)
			meteringKeys = meteringKeys[:1]
			meteringItemBatch = meteringItemBatch[:0]
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

func (l *LabelerManager) recvDumpPlatform(conn *net.UDPConn, remote *net.UDPAddr, arg *bytes.Buffer) {
	key := DumpKey{}
	buffer := bytes.Buffer{}

	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&key); err != nil {
		log.Error(err)
		debug.SendToClient(conn, remote, 1, nil)
		return
	}

	info := l.policyTable.GetEndpointInfo(key.Mac, IpFromUint32(key.Ip), key.InPort)
	if info == nil {
		log.Warningf("GetEndpointInfo(%+v) return nil", key)
		debug.SendToClient(conn, remote, 1, nil)
		return
	}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(info); err != nil {
		log.Errorf("encoder.Encode: %s", err)
		debug.SendToClient(conn, remote, 1, nil)
		return
	}
	debug.SendToClient(conn, remote, 0, &buffer)
}

func (l *LabelerManager) recvDumpAcl(conn *net.UDPConn, remote *net.UDPAddr, arg *bytes.Buffer, queryType uint16) {
	key := datatype.LookupKey{}
	buffer := bytes.Buffer{}

	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&key); err != nil {
		log.Error(err)
		debug.SendToClient(conn, remote, 1, nil)
		return
	}

	info := make([]string, 0, l.readQueuesCount)
	switch queryType {
	case LABELER_CMD_DUMP_ACL:
		for i := 0; i < l.readQueuesCount; i++ {
			key.FastIndex = i
			endpoint, policy := l.policyTable.LookupAllByKey(&key)
			info = append(info, fmt.Sprintf("GoRoutine-%d: EndPoint: {Src: %+v Dst: %+v} Policy: %+v", i, endpoint.SrcInfo, endpoint.DstInfo, policy))
		}
	case LABELER_CMD_DUMP_FIRST_ACL:
		endpoint, policy := l.policyTable.GetPolicyByFirstPath(&key)
		info = append(info, fmt.Sprintf("EndPoint: {Src: %+v Dst: %+v} Policy: %+v", endpoint.SrcInfo, endpoint.DstInfo, policy))
	case LABELER_CMD_DUMP_FAST_ACL:
		for i := 0; i < l.readQueuesCount; i++ {
			key.FastIndex = i
			endpoint, policy := l.policyTable.GetPolicyByFastPath(&key)
			info = append(info, fmt.Sprintf("GoRoutine-%d: EndPoint: {Src: %+v Dst: %+v} Policy: %+v", i, endpoint.SrcInfo, endpoint.DstInfo, policy))
		}
	}

	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(strings.Join(info, "\n\t")); err != nil {
		log.Errorf("encoder.Encode: %s", err)
		debug.SendToClient(conn, remote, 1, nil)
		return
	}
	debug.SendToClient(conn, remote, 0, &buffer)
}

func (l *LabelerManager) recvShowAcl(conn *net.UDPConn, remote *net.UDPAddr, arg *bytes.Buffer) {
	acls := l.policyTable.GetAcl()

	first, fast := l.policyTable.GetHitStatus()
	output := fmt.Sprintf("FirstHits: %d FastHits: %d", first, fast)
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(&output); err != nil {
		log.Errorf("encoder.Encode: %s", err)
	}
	debug.SendToClient(conn, remote, 0, &buffer)

	for _, acl := range policy.SortAclsById(acls) {
		buffer := bytes.Buffer{}
		encoder := gob.NewEncoder(&buffer)
		context := acl.String()
		// gob封装为'String: ' + context
		if len(context) >= dropletctl.DEBUG_MESSAGE_LEN-8 {
			context = context[:dropletctl.DEBUG_MESSAGE_LEN-8-3] + "..."
		}

		if err := encoder.Encode(context); err != nil {
			log.Errorf("encoder.Encode: %s", err)
			continue
		}

		debug.SendToClient(conn, remote, 0, &buffer)
		time.Sleep(2 * time.Millisecond)
	}
	buffer.Reset()
	encoder.Encode("END")
	debug.SendToClient(conn, remote, 0, &buffer)
}

func (l *LabelerManager) recvAddAcl(conn *net.UDPConn, remote *net.UDPAddr, arg *bytes.Buffer) {
	acl := policy.Acl{}

	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&acl); err != nil {
		log.Error(err)
		debug.SendToClient(conn, remote, 1, nil)
		return
	}
	log.Debug("droplet cmd add-acl:", acl)
	l.policyTable.AddAcl(&acl)
}

func (l *LabelerManager) recvDelAcl(conn *net.UDPConn, remote *net.UDPAddr, arg *bytes.Buffer) {
	var id int

	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&id); err != nil {
		log.Error(err)
		debug.SendToClient(conn, remote, 1, nil)
		return
	}
	l.policyTable.DelAcl(id)
}

func (l *LabelerManager) GetParsedIpGroupData() []*policy.IpGroupData {
	return l.rawIpGroupDatas
}

func (l *LabelerManager) recvShowIpGroup(conn *net.UDPConn, remote *net.UDPAddr, arg *bytes.Buffer) {
	ipGroups := l.GetParsedIpGroupData()
	ipGroup := &policy.IpGroupData{Id: math.MaxUint32, EpcId: math.MaxInt32} //作为命令行判断结束的条件
	ipGroups = append(ipGroups, ipGroup)
	for _, ipGroup := range ipGroups {
		buffer := bytes.Buffer{}
		encoder := gob.NewEncoder(&buffer)

		if err := encoder.Encode(ipGroup); err != nil {
			log.Errorf("encoder.Encode: %s", err)
			continue
		}

		debug.SendToClient(conn, remote, 0, &buffer)
		time.Sleep(2 * time.Millisecond)
	}
}
