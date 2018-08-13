package labeler

import (
	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"

	"gitlab.x.lan/yunshan/droplet/handler"
)

var log = logging.MustGetLogger("labeler")

type LabelerManager struct {
	policyTable   *policy.PolicyTable
	readQueue     queue.QueueReader
	meteringQueue queue.QueueWriter
	appQueue      []queue.QueueWriter
	running       bool
}

func NewLabelerManager(readQueue queue.QueueReader, meteringQueue queue.QueueWriter, appQueue ...queue.QueueWriter) *LabelerManager {
	return &LabelerManager{
		policyTable:   policy.NewPolicyTable(policy.ACTION_FLOW_STAT),
		readQueue:     readQueue,
		meteringQueue: meteringQueue,
		appQueue:      appQueue,
	}
}

func (l *LabelerManager) OnPlatformDataChange(data []*policy.PlatformData) {
	l.policyTable.UpdateInterfaceData(data)
}

func (l *LabelerManager) OnServiceDataChange(data []*policy.ServiceData) {
	l.policyTable.UpdateServiceData(data)
}

func (l *LabelerManager) OnIpGroupDataChange(data []*policy.IpGroupData) {
	l.policyTable.UpdateIpGroupData(data)
}

func (l *LabelerManager) GetData(key *policy.LookupKey) {
	data, _ := l.policyTable.LookupAllByKey(key)
	if data != nil {
		log.Debug("QUERY KEY:", key, "SRC:", data.SrcInfo, "DST:", data.DstInfo)
	}
}

func (l *LabelerManager) GetPolicy(packet *handler.MetaPacket) {
	key := &policy.LookupKey{
		SrcMac:      Mac2Uint64(packet.MacSrc),
		DstMac:      Mac2Uint64(packet.MacDst),
		SrcIp:       packet.IpSrc,
		DstIp:       packet.IpDst,
		SrcPort:     packet.PortSrc,
		DstPort:     packet.PortDst,
		Vlan:        packet.Vlan,
		Proto:       uint8(packet.Proto),
		Ttl:         packet.TTL,
		RxInterface: packet.InPort,
	}

	data, policy := l.policyTable.LookupAllByKey(key)
	if data != nil {
		packet.EndpointData = data
		log.Debug("QUERY PACKET:", packet, "SRC:", data.SrcInfo, "DST:", data.DstInfo)
	}

	if policy != nil {
		log.Debug("POLICY", policy)
	}
}

func cloneMetaPacket(src *handler.MetaPacket) *handler.MetaPacket {
	newPacket := *src
	if src.EndpointData != nil {
		endpointData := &policy.EndpointData{}
		if src.EndpointData.SrcInfo != nil {
			endpointData.SrcInfo = &policy.EndpointInfo{}
			*endpointData.SrcInfo = *src.EndpointData.SrcInfo
		}
		if src.EndpointData.DstInfo != nil {
			endpointData.DstInfo = &policy.EndpointInfo{}
			*endpointData.DstInfo = *src.EndpointData.DstInfo
		}
		newPacket.EndpointData = endpointData
	}

	return &newPacket
}

//FIXME:  临时方案后面这部分代码需要删除
func convertMetaPacketToTaggedMetering(metaPacket *handler.MetaPacket) *datatype.TaggedMetering {
	var l3EpcId0, l3EpcId1 uint32
	var groupIds0, groupIds1 []uint32
	if metaPacket.EndpointData != nil {
		if metaPacket.EndpointData.SrcInfo != nil {
			groupIds0 = metaPacket.EndpointData.SrcInfo.GroupIds
			l3EpcId0 = uint32(metaPacket.EndpointData.SrcInfo.L3EpcId)
		}
		if metaPacket.EndpointData.DstInfo != nil {
			groupIds1 = metaPacket.EndpointData.DstInfo.GroupIds
			l3EpcId1 = uint32(metaPacket.EndpointData.DstInfo.L3EpcId)
		}
	}

	metering := datatype.Metering{
		Exporter:     *datatype.NewIPFromString(metaPacket.Exporter.String()),
		Timestamp:    metaPacket.Timestamp,
		InPort0:      metaPacket.InPort,
		VLAN:         metaPacket.Vlan,
		IPSrc:        *datatype.NewIPFromInt(metaPacket.IpSrc),
		IPDst:        *datatype.NewIPFromInt(metaPacket.IpDst),
		Proto:        metaPacket.Proto,
		PortSrc:      metaPacket.PortSrc,
		PortDst:      metaPacket.PortDst,
		ByteCount0:   uint64(metaPacket.PacketLen),
		ByteCount1:   0,
		PacketCount0: 1,
		PacketCount1: 0,
		L3EpcID0:     l3EpcId0,
		L3EpcID1:     l3EpcId1,
	}
	tag := datatype.Tag{
		GroupIDs0: groupIds0,
		GroupIDs1: groupIds1,
	}
	return &datatype.TaggedMetering{
		Metering: metering,
		Tag:      tag,
	}
}

func (l *LabelerManager) run() {
	for l.running {
		packet := l.readQueue.Get().(*handler.MetaPacket)
		l.GetPolicy(packet)
		for _, queue := range l.appQueue {
			newPacket := cloneMetaPacket(packet)
			queue.Put(newPacket)
		}
		l.meteringQueue.Put(convertMetaPacketToTaggedMetering(packet))
	}

	log.Info("Labeler manager exit")
}

func (l *LabelerManager) Start() {
	if !l.running {
		l.running = true
		log.Info("Start labeler manager")
		go l.run()
	}
}

func (l *LabelerManager) Stop(wait bool) {
	if l.running {
		log.Info("Stop labeler manager")
		l.running = false
	}
}
