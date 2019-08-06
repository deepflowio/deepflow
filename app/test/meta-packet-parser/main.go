package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	it "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	"gitlab.x.lan/yunshan/droplet/app/common/tag"
	"gitlab.x.lan/yunshan/droplet/app/usage"
)

var policyRegex = regexp.MustCompile(`{GID: [^}]+}`)

func ipStrToInt(s string) uint32 {
	return binary.BigEndian.Uint32(net.ParseIP(s).To4())
}

func portStrToInt(s string) uint16 {
	if d, err := strconv.Atoi(s); err == nil {
		return uint16(d)
	} else {
		return 0
	}
}

func parseEndpoint(d string) *it.EndpointInfo {
	info := &it.EndpointInfo{}
	fmt.Sscanf(d, "L2EpcId: %d L2DeviceType: %d L2DeviceId: %d L2End: %t L3EpcId: %d L3DeviceType: %d L3DeviceId: %d L3End: %t",
		&info.L2EpcId, &info.L2DeviceType, &info.L2DeviceId, &info.L2End, &info.L3EpcId, &info.L3DeviceType, &info.L3DeviceId, &info.L3End)
	return info
}

func parseActionFlags(f string) it.ActionFlag {
	var flag it.ActionFlag
	for _, b := range strings.Split(f, "|") {
		switch b {
		case "PC":
			flag |= it.ACTION_PACKET_COUNTING
		case "FC":
			flag |= it.ACTION_FLOW_COUNTING
		case "FS":
			flag |= it.ACTION_FLOW_STORING
		case "TFPC":
			flag |= it.ACTION_TCP_FLOW_PERF_COUNTING
		case "PC2":
			flag |= it.ACTION_PACKET_CAPTURING
		case "FMC":
			flag |= it.ACTION_FLOW_MISC_COUNTING
		case "PCB":
			flag |= it.ACTION_PACKET_COUNT_BROKERING
		case "FCB":
			flag |= it.ACTION_FLOW_COUNT_BROKERING
		case "TFPCB":
			flag |= it.ACTION_TCP_FLOW_PERF_COUNT_BROKERING
		case "GP":
			flag |= it.ACTION_GEO_POSITIONING
		}
	}
	return flag
}

func parseTagTemplates(t string) it.TagTemplate {
	var template it.TagTemplate
	for _, b := range strings.Split(t, "|") {
		switch b {
		case "N":
			template |= it.TEMPLATE_NODE
		case "NP":
			template |= it.TEMPLATE_NODE_PORT
		case "E":
			template |= it.TEMPLATE_EDGE
		case "EP":
			template |= it.TEMPLATE_EDGE_PORT
		case "P":
			template |= it.TEMPLATE_PORT
		case "AN":
			template |= it.TEMPLATE_ACL_NODE
		case "ANP":
			template |= it.TEMPLATE_ACL_NODE_PORT
		case "AE":
			template |= it.TEMPLATE_ACL_EDGE
		case "AEP":
			template |= it.TEMPLATE_ACL_EDGE_PORT
		case "AP":
			template |= it.TEMPLATE_ACL_PORT
		case "AEP+":
			template |= it.TEMPLATE_ACL_EDGE_PORT_ALL
		}
	}
	return template
}

func parseACLAction(p string) it.AclAction {
	var gid it.ACLID
	var directions it.DirectionType
	var flags, templates string
	fmt.Sscanf(p, "GID: %d ActionFlags: %s Directions: %d TagTemplates: %s", &gid, &flags, &directions, &templates)
	var action it.AclAction
	return action.SetACLGID(gid).SetActionFlags(parseActionFlags(flags)).SetDirections(directions).SetTagTemplates(parseTagTemplates(templates))
}

func parseData(lines []string, start, end time.Duration) *it.MetaPacket {
	mp := &it.MetaPacket{}
	fmt.Sscanf(lines[0], "timestamp: %d inport: 0x%x", &mp.Timestamp, &mp.InPort)
	if mp.Timestamp < start || mp.Timestamp >= end {
		return nil
	}
	var ipPortSrc, ipPortDst, proto string
	fmt.Sscanf(lines[2], "%s -> %s proto: %s", &ipPortSrc, &ipPortDst, &proto)
	vs := strings.Split(ipPortSrc, ":")
	mp.IpSrc = ipStrToInt(vs[0])
	mp.PortSrc = portStrToInt(vs[1])
	vs = strings.Split(ipPortDst, ":")
	mp.IpDst = ipStrToInt(vs[0])
	mp.PortDst = portStrToInt(vs[1])
	switch proto {
	case "TCP":
		mp.Protocol = layers.IPProtocolTCP
	case "UDP":
		mp.Protocol = layers.IPProtocolUDP
	}
	vs = strings.Split(lines[3], "{")
	mp.EndpointData = &it.EndpointData{}
	vss := strings.Split(vs[2], "}")
	mp.EndpointData.SrcInfo = parseEndpoint(vss[0])
	vss = strings.Split(vs[3], "}")
	mp.EndpointData.DstInfo = parseEndpoint(vss[0])

	mp.PolicyData = &it.PolicyData{}
	vs = strings.Split(lines[4], "{")
	fmt.Sscanf(vs[1], "ACLID: %d", &mp.PolicyData.ACLID)
	for _, action := range policyRegex.FindAllString(lines[4], -1) {
		aclAction := parseACLAction(action[1 : len(action)-1])
		mp.PolicyData.AclActions = append(mp.PolicyData.AclActions, aclAction)
		mp.PolicyData.ActionFlags |= aclAction.GetActionFlags()
	}

	mp.PacketLen = 1

	return mp
}

func main() {
	if len(os.Args) != 2 {
		os.Exit(0)
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		os.Exit(-1)
	}
	defer file.Close()

	startTs := uint32(1541728320)
	start := time.Second * time.Duration(startTs)
	end := start + time.Minute

	var slots [60]map[uint64]map[uint64]*app.Document

	metaPackets := make([]*it.MetaPacket, 0, 8)
	scanner := bufio.NewScanner(file)
	line := 0
	buf := make([]string, 5)
	for scanner.Scan() {
		l := scanner.Text()
		if l == "--" {
			continue
		}
		buf[line] = l
		line++
		if line == 5 {
			if mp := parseData(buf, start, end); mp != nil {
				metaPackets = append(metaPackets, mp)
			}
			line = 0
		}
	}

	processor := usage.NewProcessor()
	processor.Prepare()
	for _, m := range metaPackets {
		docs := processor.Process(m, true)
		for _, d := range docs {
			doc := d.(*app.Document)
			dt := doc.Timestamp - startTs
			if slots[dt] == nil {
				slots[dt] = make(map[uint64]map[uint64]*app.Document)
			}
			key0, key1 := tag.GetFastID(doc.Tag.(*zerodoc.Tag))
			if inner, in := slots[dt][key0]; in {
				if oldDoc, in := inner[key1]; in {
					oldDoc.ConcurrentMerge(doc.Meter)
				} else {
					slots[dt][key0][key1] = app.CloneDocument(doc)
				}
			} else {
				slots[dt][key0] = make(map[uint64]*app.Document)
				slots[dt][key0][key1] = app.CloneDocument(doc)
			}
		}
	}

	aggs := make(map[uint64]map[uint64]*app.Document)
	for _, slot := range slots {
		for key0, inner := range slot {
			if _, in := aggs[key0]; !in {
				aggs[key0] = make(map[uint64]*app.Document)
			}
			for key1, doc := range inner {
				if oldDoc, in := aggs[key0][key1]; in {
					oldDoc.SequentialMerge(doc.Meter)
				} else {
					aggs[key0][key1] = app.CloneDocument(doc)
					aggs[key0][key1].Timestamp = startTs
				}
			}
		}
	}

	//	for _, doc := range aggs {
	//		if doc.GetCode() == 0x0000008200000000 || doc.GetCode() == 0x0000008000000010 {
	//			fmt.Println(doc)
	//		}
	//	}
}
