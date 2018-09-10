package labeler

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
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
	LABELER_CMD_DUMP_ACL
)

type DumpKey struct {
	Mac    uint64
	Ip     uint32
	InPort uint32
}

func NewLabelerManager(readQueue queue.QueueReader) *LabelerManager {
	labeler := &LabelerManager{
		policyTable: policy.NewPolicyTable(datatype.ACTION_FLOW_STAT),
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

func (l *LabelerManager) OnPolicyDataChange(data []*policy.Acl) {
	l.policyTable.UpdateAclData(data)
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

func (l *LabelerManager) GetPolicy(packet *datatype.MetaPacket) *datatype.PolicyData {
	key := &datatype.LookupKey{
		SrcMac:  uint64(packet.MacSrc),
		DstMac:  uint64(packet.MacDst),
		SrcIp:   uint32(packet.IpSrc),
		DstIp:   uint32(packet.IpDst),
		SrcPort: packet.PortSrc,
		DstPort: packet.PortDst,
		EthType: packet.EthType,
		Vlan:    packet.Vlan,
		Proto:   uint8(packet.Protocol),
		Ttl:     packet.TTL,
		L2End0:  packet.L2End0,
		L2End1:  packet.L2End1,
		Tap:     GetTapType(packet.InPort),
		Invalid: packet.Invalid,
	}

	packet.EndpointData, packet.PolicyData = l.policyTable.LookupAllByKey(key)
	log.Debug("QUERY PACKET:", packet, "ENDPOINTDATA:", packet.EndpointData, "POLICYDATA:", packet.PolicyData)
	return packet.PolicyData
}

func (l *LabelerManager) run() {
	for l.running {
		packet := l.readQueue.Get().(*datatype.MetaPacket)
		action := l.GetPolicy(packet)
		if (action.ActionList & datatype.ACTION_PACKET_STAT) != 0 {
			l.appQueues[METERING_QUEUE].Put(packet)
		}
		if (action.ActionList & datatype.ACTION_FLOW_STAT) != 0 {
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

func (l *LabelerManager) recvDumpAcl(conn *net.UDPConn, port int, arg *bytes.Buffer) {
	key := datatype.LookupKey{}
	buffer := bytes.Buffer{}

	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&key); err != nil {
		log.Error(err)
		dropletctl.SendToDropletCtl(conn, port, 1, nil)
		return
	}

	endpoint, policy := l.policyTable.LookupAllByKey(&key)
	info := fmt.Sprintf("EndPoint: {Src: %+v Dst: %+v} Policy: %+v", endpoint.SrcInfo, endpoint.DstInfo, policy)
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
	case LABELER_CMD_DUMP_ACL:
		l.recvDumpAcl(conn, port, arg)
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

func parseTapType(s string) datatype.TapType {
	switch s {
	case "isp":
		return datatype.TAP_ISP
	case "tor":
		return datatype.TAP_TOR
	default:
		return 0
	}
}

func newLookupKey(cmdLine string) *datatype.LookupKey {
	key := &datatype.LookupKey{}
	keyValues := strings.Split(cmdLine, ",")
	for _, keyValue := range keyValues {
		parts := strings.Split(keyValue, "=")
		switch parts[0] {
		case "tap":
			key.Tap = parseTapType(parts[1])
			if key.Tap != datatype.TAP_TOR && key.Tap != datatype.TAP_ISP {
				fmt.Printf("unknown tap type from: %s\n", cmdLine)
				return nil
			}
		case "inport":
			inport, err := parseUint(parts[1])
			if err != nil {
				fmt.Printf("%s: %v\n", cmdLine, err)
				return nil
			}
			key.RxInterface = inport
		case "smac":
			mac, err := net.ParseMAC(parts[1])
			if err != nil {
				fmt.Printf("unknown mac address from: %s[%v]\n", cmdLine, err)
				return nil
			}
			key.SrcMac = Mac2Uint64(mac)
		case "dmac":
			mac, err := net.ParseMAC(parts[1])
			if err != nil {
				fmt.Printf("unknown mac address from: %s[%v]\n", cmdLine, err)
				return nil
			}
			key.DstMac = Mac2Uint64(mac)
		case "vlan":
			vlan, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Printf("unknown vlan from: %s[%v]\n", cmdLine, err)
				return nil
			}
			key.Vlan = uint16(vlan)
		case "eth_type":
			ethType, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Printf("unknown eth_type from: %s[%v]\n", cmdLine, err)
				return nil
			}
			key.EthType = layers.EthernetType(ethType)
		case "sip":
			key.SrcIp = IpToUint32(net.ParseIP(parts[1]))
		case "dip":
			key.DstIp = IpToUint32(net.ParseIP(parts[1]))
		case "proto":
			proto, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Printf("unknown proto from: %s[%v]\n", cmdLine, err)
				return nil
			}
			key.Proto = uint8(proto)
		case "sport":
			port, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Printf("unknown port from: %s[%v]\n", cmdLine, err)
				return nil
			}
			key.SrcPort = uint16(port)
		case "dport":
			port, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Printf("unknown port from: %s[%v]\n", cmdLine, err)
				return nil
			}
			key.DstPort = uint16(port)
		default:
			fmt.Printf("unknown key %s from %s\n", parts[0], cmdLine)
			return nil
		}
	}
	return key
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

func sendLookupKey(cmdLine string) (*bytes.Buffer, error) {
	key := newLookupKey(cmdLine)
	if key == nil {
		return nil, errors.New("input error!")
	}
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(key); err != nil {
		return nil, err
	}
	_, result, err := dropletctl.SendToDroplet(dropletctl.DROPLETCTL_LABELER, LABELER_CMD_DUMP_ACL, &buffer)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func sendDumpKey(cmdLine string) (*bytes.Buffer, error) {
	key := newDumpKey(cmdLine)
	if key == nil {
		return nil, errors.New("input error!")
	}
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(key); err != nil {
		return nil, err
	}
	_, result, err := dropletctl.SendToDroplet(dropletctl.DROPLETCTL_LABELER, LABELER_CMD_DUMP_PLATFORM, &buffer)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func dumpPlatform(cmdLine string) {
	result, err := sendDumpKey(cmdLine)
	if err != nil {
		fmt.Println(err)
		return
	}
	info := datatype.EndpointInfo{}
	decoder := gob.NewDecoder(result)
	if err := decoder.Decode(&info); err != nil {
		log.Error(err)
		return
	}
	fmt.Printf("%s:\n\t%+v\n", cmdLine, info)
}

func dumpAcl(cmdLine string) {
	result, err := sendLookupKey(cmdLine)
	if err != nil {
		fmt.Println(err)
		return
	}
	var info string
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
	dumpAcl := &cobra.Command{
		Use:   "dump-acl {filter}",
		Short: "show policy list",
		Long: "droplet-ctl labeler dump-acl {[key=value]+}\n" +
			"key list:\n" +
			"\ttap         use 'isp|tor'\n" +
			"\tinport      capture interface mac suffix\n" +
			"\tsmac/dmac   packet mac address\n" +
			"\teth_type    packet eth type\n" +
			"\tvlan        packet vlan\n" +
			"\tsip/dip     packet ip address\n" +
			"\tproto       packet ip proto\n" +
			"\tsport/dport packet port",
		Example: "droplet-ctl labeler dump-acl inport=0x10000,smac=12:34:56:78:9a:bc,sip=127.0.0.1",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				fmt.Printf("filter is nil, Example: %s\n", cmd.Example)
				return
			}
			dumpAcl(args[0])
		},
	}
	labeler.AddCommand(dump)
	labeler.AddCommand(dumpAcl)
	return labeler
}
