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

type QueueType uint8

const (
	FLOW_QUEUE QueueType = iota
	METERING_QUEUE
	MAX_QUEUE_NUM
)

type LabelerManager struct {
	policyTable *policy.PolicyTable
	readQueue   queue.QueueReader
	appQueues   [MAX_QUEUE_NUM]queue.QueueWriter
	running     bool
}

const (
	LABELER_CMD_DUMP_PLATFORM = iota
)

type DumpKey struct {
	Mac    uint64
	Ip     uint32
	InPort uint32
}

func NewLabelerManager(readQueue queue.QueueReader) *LabelerManager {
	labeler := &LabelerManager{
		policyTable: policy.NewPolicyTable(policy.ACTION_FLOW_STAT),
		readQueue:   readQueue,
	}
	dropletctl.Register(dropletctl.DROPLETCTL_LABELER, labeler)
	return labeler
}

func (l *LabelerManager) RegisterAppQueue(queueType QueueType, appQueue queue.QueueWriter) {
	l.appQueues[queueType] = appQueue
}

func (l *LabelerManager) OnPlatformDataChange(data []*datatype.PlatformData) {
	l.policyTable.UpdateInterfaceData(data)
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

func GetTapType(inPort uint32) datatype.TapType {
	if policy.PortInDeepflowExporter(inPort) {
		return datatype.TAP_TOR
	}
	return datatype.TAP_ISP
}

func (l *LabelerManager) GetPolicy(packet *datatype.MetaPacket) *policy.Action {
	key := &datatype.LookupKey{
		SrcMac:      uint64(packet.MacSrc),
		DstMac:      uint64(packet.MacDst),
		SrcIp:       uint32(packet.IpSrc),
		DstIp:       uint32(packet.IpDst),
		SrcPort:     packet.PortSrc,
		DstPort:     packet.PortDst,
		EthType:     packet.EthType,
		Vlan:        packet.Vlan,
		Proto:       uint8(packet.Protocol),
		Ttl:         packet.TTL,
		L2End0:      packet.L2End0,
		L2End1:      packet.L2End1,
		RxInterface: packet.InPort,
		Tap:         GetTapType(packet.InPort),
	}

	data, policy := l.policyTable.LookupAllByKey(key)
	if data != nil {
		packet.EndpointData = data
		log.Debug("QUERY PACKET:", packet, "SRC:", data.SrcInfo, "DST:", data.DstInfo)
	}

	if policy != nil {
		log.Debug("POLICY", policy)
	}

	return policy
}

func cloneMetaPacket(src *datatype.MetaPacket) *datatype.MetaPacket {
	newPacket := *src
	srcInfo := *src.EndpointData.SrcInfo
	dstInfo := *src.EndpointData.DstInfo
	newPacket.EndpointData = &datatype.EndpointData{
		SrcInfo: &srcInfo,
		DstInfo: &dstInfo,
	}

	return &newPacket
}

func (l *LabelerManager) run() {
	for l.running {
		packet := l.readQueue.Get().(*datatype.MetaPacket)
		action := l.GetPolicy(packet)
		if (action.ActionTypes&policy.ACTION_PACKET_STAT) != 0 && l.appQueues[METERING_QUEUE] != nil {
			l.appQueues[METERING_QUEUE].Put(cloneMetaPacket(packet))
		}
		if (action.ActionTypes&policy.ACTION_FLOW_STAT) != 0 && l.appQueues[FLOW_QUEUE] != nil {
			l.appQueues[FLOW_QUEUE].Put(packet)
		}
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
