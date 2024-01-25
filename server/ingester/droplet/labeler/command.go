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
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/policy"
	. "github.com/deepflowio/deepflow/server/libs/utils"

	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl/rpc"
)

type command struct {
	label *LabelerManager
}

func (c *command) init(label *LabelerManager) {
	c.label = label
}

func (c *command) recvDumpPlatform(conn *net.UDPConn, remote *net.UDPAddr, arg *bytes.Buffer) {
	key := DumpKey{}
	buffer := bytes.Buffer{}
	label := c.label

	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&key); err != nil {
		log.Error(err)
		debug.SendToClient(conn, remote, 1, nil)
		return
	}

	info := label.policyTable.GetEndpointInfo(key.Mac, IpFromUint32(key.Ip), key.InPort)
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

func (c *command) recvDumpAcl(conn *net.UDPConn, remote *net.UDPAddr, arg *bytes.Buffer, queryType uint16) {
	key := datatype.LookupKey{}
	buffer := bytes.Buffer{}
	label := c.label

	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&key); err != nil {
		log.Error(err)
		debug.SendToClient(conn, remote, 1, nil)
		return
	}

	info := make([]string, 0, len(label.lookupKey))
	switch queryType {
	case LABELER_CMD_DUMP_ACL:
		for i := 0; i < len(label.lookupKey); i++ {
			key.FastIndex = i
			endpoint, policy := &datatype.EndpointData{}, &datatype.PolicyData{}
			label.policyTable.LookupAllByKey(&key, policy, endpoint)
			info = append(info, fmt.Sprintf("GoRoutine-%d: EndPoint: {Src: %+v Dst: %+v} Policy: %+v", i, endpoint.SrcInfo, endpoint.DstInfo, policy))
		}
	case LABELER_CMD_DUMP_FIRST_ACL:
		endpoint, policy := label.policyTable.GetPolicyByFirstPath(&key)
		info = append(info, fmt.Sprintf("EndPoint: {Src: %+v Dst: %+v} Policy: %+v", endpoint.SrcInfo, endpoint.DstInfo, policy))
	case LABELER_CMD_DUMP_FAST_ACL:
		for i := 0; i < len(label.lookupKey); i++ {
			key.FastIndex = i
			endpoint, policy := label.policyTable.GetPolicyByFastPath(&key)
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

func (c *command) recvShowAcl(conn *net.UDPConn, remote *net.UDPAddr, arg *bytes.Buffer) {
	label := c.label
	acls := label.policyTable.GetAcl()

	first, fast := label.policyTable.GetHitStatus()
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
		if len(context) >= ingesterctl.DEBUG_MESSAGE_LEN-8 {
			context = context[:ingesterctl.DEBUG_MESSAGE_LEN-8-3] + "..."
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

func (c *command) recvAddAcl(conn *net.UDPConn, remote *net.UDPAddr, arg *bytes.Buffer) {
	acl := policy.Acl{}
	label := c.label

	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&acl); err != nil {
		log.Error(err)
		debug.SendToClient(conn, remote, 1, nil)
		return
	}
	log.Debug("droplet cmd add-acl:", acl)
	label.policyTable.AddAcl(&acl)
}

func (c *command) recvDelAcl(conn *net.UDPConn, remote *net.UDPAddr, arg *bytes.Buffer) {
	var id int

	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&id); err != nil {
		log.Error(err)
		debug.SendToClient(conn, remote, 1, nil)
		return
	}
	c.label.policyTable.DelAcl(id)
}

func (c *command) GetParsedIpGroupData() []*policy.IpGroupData {
	return c.label.rawIpGroupDatas
}

func (c *command) recvShowIpGroup(conn *net.UDPConn, remote *net.UDPAddr, arg *bytes.Buffer) {
	ipGroups := c.label.GetParsedIpGroupData()
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

func (c *command) RecvCommand(conn *net.UDPConn, remote *net.UDPAddr, operate uint16, arg *bytes.Buffer) {
	switch operate {
	case LABELER_CMD_DUMP_PLATFORM:
		c.recvDumpPlatform(conn, remote, arg)
	case LABELER_CMD_DUMP_ACL, LABELER_CMD_DUMP_FIRST_ACL, LABELER_CMD_DUMP_FAST_ACL:
		c.recvDumpAcl(conn, remote, arg, operate)
	case LABELER_CMD_SHOW_ACL:
		c.recvShowAcl(conn, remote, arg)
	case LABELER_CMD_ADD_ACL:
		c.recvAddAcl(conn, remote, arg)
	case LABELER_CMD_DEL_ACL:
		c.recvDelAcl(conn, remote, arg)
	case LABELER_CMD_SHOW_IPGROUP:
		c.recvShowIpGroup(conn, remote, arg)
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
		return datatype.TAP_CLOUD
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
		case "capture_network_type":
			key.TapType = parseTapType(parts[1])
			if key.TapType >= datatype.TAP_MAX {
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
	_, result, err := debug.SendToServer(ingesterctl.INGESTERCTL_LABELER, debug.ModuleOperate(queryType), &buffer)
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
	_, result, err := debug.SendToServer(ingesterctl.INGESTERCTL_LABELER, LABELER_CMD_DUMP_PLATFORM, &buffer)
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
	conn, result, err := debug.SendToServer(ingesterctl.INGESTERCTL_LABELER, LABELER_CMD_SHOW_ACL, nil)
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
	debug.SendToServer(ingesterctl.INGESTERCTL_LABELER, LABELER_CMD_DEL_ACL, &buffer)
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
			acl.Id = uint32(id)
		case "proto":
			proto, err := strconv.Atoi(keyValue[1])
			if err != nil || proto < 0 || proto > 255 {
				fmt.Printf("invalid proto %s from %s\n", keyValue[1], args[0])
				return nil
			}
			acl.Proto = uint16(proto)
		case "capture_network_type":
			switch keyValue[1] {
			case "any":
				acl.TapType = datatype.TAP_ANY
			case "tor":
				acl.TapType = datatype.TAP_CLOUD
			default:
				typeId, err := strconv.Atoi(keyValue[1])
				if err != nil {
					fmt.Printf("invalid capture_network_type %s from %s\n", keyValue[1], args[0])
					return nil
				}
				acl.TapType = datatype.TapType(typeId)
			}
		case "port":
			port, err := strconv.Atoi(keyValue[1])
			if err != nil || port > 65535 || port < 0 {
				fmt.Printf("invalid port %s from %s\n", keyValue[1], args[0])
				return nil
			}
			acl.DstPortRange = make([]datatype.PortRange, 0)
			acl.DstPortRange = append(acl.DstPortRange,
				datatype.NewPortRange(uint16(port), uint16(port)))
		default:
			fmt.Printf("invalid key from %s\n", args[0])
			return nil
		}
	}
	if acl.Id == 0 {
		fmt.Printf("invalid input %s\n", args[0])
		return nil
	}
	acl.NpbActions = append(acl.NpbActions, datatype.ToNpbActions(acl.Id, 0, datatype.NPB_TUNNEL_TYPE_PCAP, 0, 0))
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
	debug.SendToServer(ingesterctl.INGESTERCTL_LABELER, LABELER_CMD_ADD_ACL, &buffer)
}

func showIpGroup() {
	conn, result, err := debug.SendToServer(ingesterctl.INGESTERCTL_LABELER, LABELER_CMD_SHOW_IPGROUP, nil)
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

func RegisterCommand(moduleId debug.ModuleId) *cobra.Command {
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
			"\tcapture_network_type         use '[1-2,4-30]|tor'\n" +
			"\tsmac/dmac   packet mac address\n" +
			"\teth_type    packet eth type\n" +
			"\tvlan        packet vlan\n" +
			"\tsip/dip     packet ip address\n" +
			"\tproto       packet ip proto\n" +
			"\tsport/dport packet port\n" +
			"\ttype        use query type 'normal|first|fast' default normal",
		Example: "droplet-ctl labeler dump-acl capture_network_type=tor,smac=12:34:56:78:9a:bc,sip=127.0.0.1",
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
			"\tcapture_network_type                use '[1-2,4-30]|tor|any'\n" +
			"\tvlan               packet vlan\n" +
			"\tsgroup/dgroup      group id\n" +
			"\tproto              packet ip proto\n" +
			"\tport               packet port\n\n",
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
