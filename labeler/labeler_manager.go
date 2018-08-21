package labeler

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/op/go-logging"
	"github.com/spf13/cobra"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"

	"gitlab.x.lan/yunshan/droplet/dropletctl"
)

var log = logging.MustGetLogger("labeler")

type LabelerManager struct {
	policyTable   *policy.PolicyTable
	readQueue     queue.QueueReader
	meteringQueue queue.QueueWriter
	appQueue      []queue.QueueWriter
	running       bool
}

const (
	LABELER_CMD_DUMP_PLATFORM = iota
)

type DumpKey struct {
	Mac    uint64
	Ip     uint32
	InPort uint32
}

func NewLabelerManager(readQueue queue.QueueReader, meteringQueue queue.QueueWriter, appQueue ...queue.QueueWriter) *LabelerManager {
	labeler := &LabelerManager{
		policyTable:   policy.NewPolicyTable(policy.ACTION_FLOW_STAT),
		readQueue:     readQueue,
		meteringQueue: meteringQueue,
		appQueue:      appQueue,
	}
	dropletctl.Register(dropletctl.DROPLETCTL_LABELER, labeler)
	return labeler
}

func (l *LabelerManager) OnPlatformDataChange(data []*datatype.PlatformData) {
	l.policyTable.UpdateInterfaceData(data)
}

func (l *LabelerManager) OnServiceDataChange(data []*policy.ServiceData) {
	l.policyTable.UpdateServiceData(data)
}

func (l *LabelerManager) OnIpGroupDataChange(data []*policy.IpGroupData) {
	l.policyTable.UpdateIpGroupData(data)
}

func (l *LabelerManager) GetData(key *datatype.LookupKey) {
	data, _ := l.policyTable.LookupAllByKey(key)
	if data != nil {
		log.Debug("QUERY KEY:", key, "SRC:", data.SrcInfo, "DST:", data.DstInfo)
	}
}

func (l *LabelerManager) GetPolicy(packet *datatype.MetaPacket) {
	key := &datatype.LookupKey{
		SrcMac:      uint64(packet.MacSrc),
		DstMac:      uint64(packet.MacDst),
		SrcIp:       uint32(packet.IpSrc),
		DstIp:       uint32(packet.IpDst),
		SrcPort:     packet.PortSrc,
		DstPort:     packet.PortDst,
		Vlan:        packet.Vlan,
		Proto:       uint8(packet.Protocol),
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

func cloneMetaPacket(src *datatype.MetaPacket) *datatype.MetaPacket {
	newPacket := *src
	if src.EndpointData != nil {
		endpointData := &datatype.EndpointData{}
		if src.EndpointData.SrcInfo != nil {
			endpointData.SrcInfo = &datatype.EndpointInfo{}
			*endpointData.SrcInfo = *src.EndpointData.SrcInfo
		}
		if src.EndpointData.DstInfo != nil {
			endpointData.DstInfo = &datatype.EndpointInfo{}
			*endpointData.DstInfo = *src.EndpointData.DstInfo
		}
		newPacket.EndpointData = endpointData
	}

	return &newPacket
}

//FIXME:  临时方案后面这部分代码需要删除
func convertMetaPacketToTaggedMetering(metaPacket *datatype.MetaPacket) *datatype.TaggedMetering {
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
		Exporter:     *datatype.NewIPFromInt(uint32(metaPacket.Exporter)),
		Timestamp:    metaPacket.Timestamp,
		InPort0:      metaPacket.InPort,
		VLAN:         metaPacket.Vlan,
		IPSrc:        *datatype.NewIPFromInt(uint32(metaPacket.IpSrc)),
		IPDst:        *datatype.NewIPFromInt(uint32(metaPacket.IpDst)),
		Proto:        metaPacket.Protocol,
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
		packet := l.readQueue.Get().(*datatype.MetaPacket)
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

func (l *LabelerManager) recvDumpPlatform(conn *net.UDPConn, port int, arg *bytes.Buffer) {
	key := DumpKey{}
	buffer := bytes.Buffer{}

	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&key); err != nil {
		log.Error(err)
		dropletctl.SendToDropletCtl(conn, port, 1, nil)
		return
	}

	info := l.policyTable.GetEndpointInfo(key.Mac, key.Ip, key.InPort)
	if info == nil {
		log.Warningf("GetEndpointInfo(%+v) return nil", key)
		dropletctl.SendToDropletCtl(conn, port, 1, nil)
		return
	}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(info); err != nil {
		log.Errorf("encoder.Encode: %s", err)
		dropletctl.SendToDropletCtl(conn, port, 1, nil)
		return
	}
	dropletctl.SendToDropletCtl(conn, port, 0, &buffer)
}

func (l *LabelerManager) RecvCommand(conn *net.UDPConn, port int, operate uint16, arg *bytes.Buffer) {
	switch operate {
	case LABELER_CMD_DUMP_PLATFORM:
		l.recvDumpPlatform(conn, port, arg)
	}
}

func parseUint(s string) (uint32, error) {
	if s[0:2] == "0x" {
		x, err := strconv.ParseUint(s[2:], 16, 64)
		return uint32(x), err
	} else {
		x, err := strconv.ParseUint(s, 10, 64)
		return uint32(x), err
	}
}

func newDumpKey(cmdLine string) *DumpKey {
	key := &DumpKey{}
	keyValues := strings.Split(cmdLine, ",")
	for _, keyValue := range keyValues {
		parts := strings.Split(keyValue, "=")
		switch parts[0] {
		case "mac":
			mac, err := net.ParseMAC(parts[1])
			if err != nil {
				fmt.Printf("unknown mac address from: %s[%v]\n", cmdLine, err)
				return nil
			}
			key.Mac = Mac2Uint64(mac)
		case "ip":
			key.Ip = IpToUint32(net.ParseIP(parts[1]))
		case "inport":
			inport, err := parseUint(parts[1])
			if err != nil {
				fmt.Printf("%s: %v\n", cmdLine, err)
				return nil
			}
			key.InPort = inport
		default:
			fmt.Printf("unknown key %s from %s\n", parts[0], cmdLine)
			return nil
		}
	}
	return key
}

func dumpPlatform(cmdLine string) {
	key := newDumpKey(cmdLine)
	if key == nil {
		return
	}
	buffer := bytes.Buffer{}
	info := datatype.EndpointInfo{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(key); err != nil {
		fmt.Println(err)
		return
	}
	_, result, err := dropletctl.SendToDroplet(dropletctl.DROPLETCTL_LABELER, LABELER_CMD_DUMP_PLATFORM, &buffer)
	if err != nil {
		log.Warning(err)
		return
	}
	decoder := gob.NewDecoder(result)
	if err := decoder.Decode(&info); err != nil {
		log.Error(err)
		return
	}
	fmt.Printf("%s:\n\t%+v\n", cmdLine, info)
}

func RegisterCommand() *cobra.Command {
	labeler := &cobra.Command{
		Use:   "labeler",
		Short: "config droplet labeler module",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with arguments 'dump-platform'.\n")
		},
	}
	dump := &cobra.Command{
		Use:     "dump-platform [filter]",
		Short:   "dump platform data infomation",
		Example: "droplet-ctl labeler dump-platform inport=1000,mac=12:34:56:78:9a:bc,ip=127.0.0.1",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				fmt.Printf("filter is nil, Example: %s\n", cmd.Example)
				return
			}
			dumpPlatform(args[0])
		},
	}
	labeler.AddCommand(dump)
	return labeler
}
