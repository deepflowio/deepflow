package labeler

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"math"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/op/go-logging"
	"github.com/spf13/cobra"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/dropletpb"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"

	"gitlab.x.lan/yunshan/droplet/dropletctl"
	"gitlab.x.lan/yunshan/droplet/dropletctl/rpc"
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
	policyTable     *policy.PolicyTable
	readQueues      queue.MultiQueueReader
	readQueuesCount int
	appQueues       [QUEUE_TYPE_MAX]queue.MultiQueueWriter
	running         bool

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
		policyTable:     policy.NewPolicyTable(datatype.ACTION_FLOW_COUNTING, count, size, disable, id),
		readQueues:      readQueues,
		readQueuesCount: count,
	}
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
	if reflect.DeepEqual(l.rawPolicyData, data) {
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
	key := &datatype.LookupKey{
		Timestamp:   packet.Timestamp,
		SrcMac:      uint64(packet.MacSrc),
		DstMac:      uint64(packet.MacDst),
		SrcIp:       uint32(packet.IpSrc),
		DstIp:       uint32(packet.IpDst),
		SrcPort:     packet.PortSrc,
		DstPort:     packet.PortDst,
		EthType:     packet.EthType,
		Vlan:        packet.Vlan,
		Proto:       uint8(packet.Protocol),
		Ttl:         getTTL(packet),
		L2End0:      packet.L2End0,
		L2End1:      packet.L2End1,
		Tap:         datatype.GetTapType(packet.InPort),
		Invalid:     packet.Invalid,
		FastIndex:   index,
		FeatureFlag: datatype.NPM,
	}

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

	info := l.policyTable.GetEndpointInfo(key.Mac, key.Ip, key.InPort)
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

func (l *LabelerManager) RecvCommand(conn *net.UDPConn, remote *net.UDPAddr, operate uint16, arg *bytes.Buffer) {
	switch operate {
	case LABELER_CMD_DUMP_PLATFORM:
		l.recvDumpPlatform(conn, remote, arg)
	case LABELER_CMD_DUMP_ACL, LABELER_CMD_DUMP_FIRST_ACL, LABELER_CMD_DUMP_FAST_ACL:
		l.recvDumpAcl(conn, remote, arg, operate)
	case LABELER_CMD_SHOW_ACL:
		l.recvShowAcl(conn, remote, arg)
	case LABELER_CMD_ADD_ACL:
		l.recvAddAcl(conn, remote, arg)
	case LABELER_CMD_DEL_ACL:
		l.recvDelAcl(conn, remote, arg)
	case LABELER_CMD_SHOW_IPGROUP:
		l.recvShowIpGroup(conn, remote, arg)
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
	case "tor":
		return datatype.TAP_TOR
	default:
		typeId, err := strconv.Atoi(s)
		if err != nil {
			fmt.Printf("unknown tapType from: %s[%v]\n", s, err)
			return 0
		}
		return datatype.TapType(typeId)
	}
}

func newLookupKey(cmdLine string) (*datatype.LookupKey, uint16) {
	key := &datatype.LookupKey{}
	keyValues := strings.Split(cmdLine, ",")
	queryType := uint16(LABELER_CMD_DUMP_ACL)
	for _, keyValue := range keyValues {
		parts := strings.Split(keyValue, "=")
		switch parts[0] {
		case "tap":
			key.Tap = parseTapType(parts[1])
			if key.Tap >= datatype.TAP_MAX {
				fmt.Printf("unknown tap type from: %s\n", cmdLine)
				return nil, queryType
			}
		case "smac":
			mac, err := net.ParseMAC(parts[1])
			if err != nil {
				fmt.Printf("unknown mac address from: %s[%v]\n", cmdLine, err)
				return nil, queryType
			}
			key.SrcMac = Mac2Uint64(mac)
		case "dmac":
			mac, err := net.ParseMAC(parts[1])
			if err != nil {
				fmt.Printf("unknown mac address from: %s[%v]\n", cmdLine, err)
				return nil, queryType
			}
			key.DstMac = Mac2Uint64(mac)
		case "vlan":
			vlan, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Printf("unknown vlan from: %s[%v]\n", cmdLine, err)
				return nil, queryType
			}
			key.Vlan = uint16(vlan)
		case "eth_type":
			ethType, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Printf("unknown eth_type from: %s[%v]\n", cmdLine, err)
				return nil, queryType
			}
			key.EthType = layers.EthernetType(ethType)
		case "sip":
			key.SrcIp = IpToUint32(net.ParseIP(parts[1]).To4())
		case "dip":
			key.DstIp = IpToUint32(net.ParseIP(parts[1]).To4())
		case "proto":
			proto, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Printf("unknown proto from: %s[%v]\n", cmdLine, err)
				return nil, queryType
			}
			key.Proto = uint8(proto)
		case "sport":
			port, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Printf("unknown port from: %s[%v]\n", cmdLine, err)
				return nil, queryType
			}
			key.SrcPort = uint16(port)
		case "dport":
			port, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Printf("unknown port from: %s[%v]\n", cmdLine, err)
				return nil, queryType
			}
			key.DstPort = uint16(port)
		case "type":
			if "first" == parts[1] {
				queryType = LABELER_CMD_DUMP_FIRST_ACL
			} else if "fast" == parts[1] {
				queryType = LABELER_CMD_DUMP_FAST_ACL
			} else if "normal" == parts[1] {
				queryType = LABELER_CMD_DUMP_ACL
			} else {
				fmt.Printf("unknown querytype from: %s \n", cmdLine)
				return nil, queryType
			}
		default:
			fmt.Printf("unknown key %s from %s\n", parts[0], cmdLine)
			return nil, queryType
		}
	}
	key.FeatureFlag = datatype.NPM
	return key, queryType
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
			key.Ip = IpToUint32(net.ParseIP(parts[1]).To4())
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
	key, queryType := newLookupKey(cmdLine)
	if key == nil {
		return nil, errors.New("input error!")
	}
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(key); err != nil {
		return nil, err
	}
	_, result, err := debug.SendToServer(dropletctl.DROPLETCTL_LABELER, debug.ModuleOperate(queryType), &buffer)
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
	_, result, err := debug.SendToServer(dropletctl.DROPLETCTL_LABELER, LABELER_CMD_DUMP_PLATFORM, &buffer)
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

func showAcl() {
	conn, result, err := debug.SendToServer(dropletctl.DROPLETCTL_LABELER, LABELER_CMD_SHOW_ACL, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	var info string
	decoder := gob.NewDecoder(result)
	if err := decoder.Decode(&info); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s\n", info)

	var context string
	for i := 1; ; i++ {
		buffer, err := debug.RecvFromServer(conn)
		if err != nil {
			fmt.Println(err)
			break
		}
		decoder := gob.NewDecoder(buffer)
		if err := decoder.Decode(&context); err != nil {
			fmt.Println(err)
			return
		}
		if context == "END" {
			break
		}
		fmt.Printf("  %4d, \t%s\n", i, context)
	}
}

func delAcl(arg string) {
	id, err := strconv.Atoi(arg)
	if id < 0 || err != nil {
		fmt.Printf("invalid id from %s\n", arg)
		return
	}
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(&id); err != nil {
		fmt.Println(err)
		return
	}
	debug.SendToServer(dropletctl.DROPLETCTL_LABELER, LABELER_CMD_DEL_ACL, &buffer)
}

func parseAcl(args []string) *policy.Acl {
	acl := &policy.Acl{}
	acl.SrcGroups = make([]uint32, 0)
	acl.DstGroups = make([]uint32, 0)

	parts := strings.Split(args[0], ",")
	for _, part := range parts {
		keyValue := strings.Split(part, "=")
		switch keyValue[0] {
		case "sgroup":
			group, err := strconv.Atoi(keyValue[1])
			if err != nil || group < 0 {
				fmt.Printf("invalid sgroup %s from %s\n", keyValue[1], args[0])
				return nil
			}
			acl.SrcGroups = append(acl.SrcGroups, uint32(group))
		case "dgroup":
			group, err := strconv.Atoi(keyValue[1])
			if err != nil || group < 0 {
				fmt.Printf("invalid sgroup %s from %s\n", keyValue[1], args[0])
				return nil
			}
			acl.DstGroups = append(acl.DstGroups, uint32(group))
		case "id":
			id, err := strconv.Atoi(keyValue[1])
			if err != nil || id < 0 {
				fmt.Printf("invalid id %s from %s\n", keyValue[1], args[0])
				return nil
			}
			acl.Id = datatype.ACLID(id)
		case "proto":
			proto, err := strconv.Atoi(keyValue[1])
			if err != nil || proto < 0 || proto > 255 {
				fmt.Printf("invalid proto %s from %s\n", keyValue[1], args[0])
				return nil
			}
			acl.Proto = uint8(proto)
		case "tap":
			switch keyValue[1] {
			case "any":
				acl.Type = datatype.TAP_ANY
			case "tor":
				acl.Type = datatype.TAP_TOR
			default:
				typeId, err := strconv.Atoi(keyValue[1])
				if err != nil {
					fmt.Printf("invalid tap %s from %s\n", keyValue[1], args[0])
					return nil
				}
				acl.Type = datatype.TapType(typeId)
			}
		case "vlan":
			vlan, err := strconv.Atoi(keyValue[1])
			if err != nil || vlan > 4096 || vlan < 0 {
				fmt.Printf("invalid vlan %s from %s\n", keyValue[1], args[0])
				return nil
			}
			acl.Vlan = uint32(vlan)
		case "port":
			port, err := strconv.Atoi(keyValue[1])
			if err != nil || port > 65535 || port < 0 {
				fmt.Printf("invalid port %s from %s\n", keyValue[1], args[0])
				return nil
			}
			acl.DstPorts = make([]uint16, 0)
			acl.DstPorts = append(acl.DstPorts, uint16(port))
		case "action":
			aclAction := datatype.AclAction(0).AddDirections(datatype.FORWARD | datatype.BACKWARD).AddTagTemplates(0xFFFF)
			switch keyValue[1] {
			case "metering":
				aclAction = aclAction.AddActionFlags(datatype.ACTION_PACKET_COUNTING | datatype.ACTION_PACKET_COUNT_BROKERING)
			case "flow":
				aclAction = aclAction.AddActionFlags(datatype.ACTION_FLOW_COUNTING | datatype.ACTION_FLOW_COUNT_BROKERING | datatype.ACTION_FLOW_STORING)
			case "all":
				aclAction = aclAction.AddActionFlags(0xFFFF)
			default:
				fmt.Printf("invalid tap %s from %s\n", keyValue[1], args[0])
				return nil
			}
			acl.Action = append(acl.Action, aclAction)
		default:
			fmt.Printf("invalid key from %s\n", args[0])
			return nil
		}
	}
	if acl.Id == 0 || len(acl.Action) == 0 {
		fmt.Printf("invalid input %s\n", args[0])
		return nil
	}
	return acl
}

func addAcl(args []string) {
	acl := parseAcl(args)
	if acl == nil {
		return
	}

	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(acl); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("acl: %+v\n", acl)
	debug.SendToServer(dropletctl.DROPLETCTL_LABELER, LABELER_CMD_ADD_ACL, &buffer)
}

func showIpGroup() {
	conn, result, err := debug.SendToServer(dropletctl.DROPLETCTL_LABELER, LABELER_CMD_SHOW_IPGROUP, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	ipGroups := make([]*policy.IpGroupData, 0, 1024)
	ipGroup := &policy.IpGroupData{}
	decoder := gob.NewDecoder(result)
	if err := decoder.Decode(ipGroup); err != nil {
		fmt.Println(err)
		return
	}
	ipGroups = append(ipGroups, ipGroup)

	for {
		ipGroup := &policy.IpGroupData{}
		buffer, err := debug.RecvFromServer(conn)
		if err != nil {
			fmt.Println(err)
			break
		}
		decoder := gob.NewDecoder(buffer)
		if err := decoder.Decode(ipGroup); err != nil {
			fmt.Println(err)
			return
		}
		if ipGroup.Id == math.MaxUint32 && ipGroup.EpcId == math.MaxInt32 {
			break
		}
		ipGroups = append(ipGroups, ipGroup)
	}

	for index, ipGroup := range policy.SortIpGroupsById(ipGroups) {
		rpc.JsonFormat(index+1, ipGroup)
	}
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
		Short: "search policy and endpoint",
		Long: "droplet-ctl labeler dump-acl {[key=value]+}\n" +
			"key list:\n" +
			"\ttap         use '[1-2,4-30]|tor'\n" +
			"\tsmac/dmac   packet mac address\n" +
			"\teth_type    packet eth type\n" +
			"\tvlan        packet vlan\n" +
			"\tsip/dip     packet ip address\n" +
			"\tproto       packet ip proto\n" +
			"\tsport/dport packet port\n" +
			"\ttype        use query type 'normal|first|fast' default normal",
		Example: "droplet-ctl labeler dump-acl tap=tor,smac=12:34:56:78:9a:bc,sip=127.0.0.1",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				fmt.Printf("filter is nil, Example: %s\n", cmd.Example)
				return
			}
			dumpAcl(args[0])
		},
	}
	showAcl := &cobra.Command{
		Use:     "show-acl",
		Short:   "show policy list",
		Example: "droplet-ctl labeler show-acl",
		Run: func(cmd *cobra.Command, args []string) {
			showAcl()
		},
	}
	delAcl := &cobra.Command{
		Use:     "del-acl {id}",
		Short:   "delete policy",
		Example: "droplet-ctl labeler del-acl 1",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				fmt.Printf("filter is nil, Example: %s\n", cmd.Example)
				return
			}
			delAcl(args[0])
		},
	}
	addAcl := &cobra.Command{
		Use:     "add-acl {[key=value]+}",
		Short:   "add policy",
		Example: "droplet-ctl labeler add-acl vlan=10,port=100,action=flow",
		Long: "droplet-ctl labeler add-acl {[key=value]+}\n" +
			"key list:\n" +
			"\tid                 acl id and action id\n" +
			"\ttap                use '[1-2,4-30]|tor|any'\n" +
			"\tvlan               packet vlan\n" +
			"\tsgroup/dgroup      group id\n" +
			"\tproto              packet ip proto\n" +
			"\tport               packet port\n" +
			"\taction             use 'flow|metering|all'\n\n" +
			"\taction: flow=ACTION_PACKET_COUNTING|ACTION_PACKET_COUNT_BROKERING\n" +
			"\t        metering=ACTION_FLOW_COUNTING|ACTION_FLOW_COUNT_BROKERING|ACTION_FLOW_STORING",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				fmt.Printf("acl is nil, Example: %s\n", cmd.Example)
				return
			}
			addAcl(args)
		},
	}
	showIpGroup := &cobra.Command{
		Use:     "show-ipGroup",
		Short:   "show parsed ipGroup list",
		Example: "droplet-ctl labeler show-ipGroup",
		Run: func(cmd *cobra.Command, args []string) {
			showIpGroup()
		},
	}
	labeler.AddCommand(dump)
	labeler.AddCommand(dumpAcl)
	labeler.AddCommand(showAcl)
	labeler.AddCommand(delAcl)
	labeler.AddCommand(addAcl)
	labeler.AddCommand(showIpGroup)
	return labeler
}
