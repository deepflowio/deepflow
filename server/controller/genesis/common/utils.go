/*
 * Copyright (c) 2023 Yunshan Networks
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

package common

import (
	"bytes"
	"compress/zlib"
	. "encoding/binary"
	"encoding/csv"
	"encoding/xml"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/common"
	"gopkg.in/yaml.v3"
	"inet.af/netaddr"
)

type VifInfo struct {
	MaskLen uint32
	Address string
	Scope   string
}

type Iface struct {
	Index     int
	PeerIndex int
	MAC       string
	Name      string
	Peer      string
	IPs       []VifInfo
}

type KVMUser struct {
	UUID  string `xml:"uuid,attr"`
	Value string `xml:",innerxml"`
}

type KVMProject struct {
	UUID  string `xml:"uuid,attr"`
	Value string `xml:",innerxml"`
}

type KVMOwner struct {
	User    KVMUser    `xml:"user"`
	Project KVMProject `xml:"project"`
}
type KVMInstance struct {
	Namespace string   `xml:"xmlns nova,attr"`
	Name      string   `xml:"name"`
	Owner     KVMOwner `xml:"owner"`
}
type KVMMetaData struct {
	Instance KVMInstance `xml:"instance"`
}

type KVMMac struct {
	Value string `xml:"address,attr"`
}

type KVMSource struct {
	Value string `xml:"bridge,attr"`
}

type KVMTarget struct {
	Value string `xml:"dev,attr"`
}

type KVMModel struct {
	Value string `xml:"type,attr"`
}

type KVMAddress struct {
	AddressValue  string `xml:"type,attr"`
	DomainValue   string `xml:"domain,attr"`
	BusValue      string `xml:"bus,attr"`
	SlotValue     string `xml:"slot,attr"`
	FunctionValue string `xml:"function,attr"`
}

type KVMInterface struct {
	Type    string     `xml:"type,attr"`
	Mac     KVMMac     `xml:"mac"`
	Source  KVMSource  `xml:"source"`
	Target  KVMTarget  `xml:"target"`
	Model   KVMModel   `xml:"model"`
	Address KVMAddress `xml:"address"`
}

type KVMDevices struct {
	Interfaces []KVMInterface `xml:"interface"`
}

type KVMDomain struct {
	Type     string      `xml:"type,attr"`
	UUID     string      `xml:"uuid"`
	Name     string      `xml:"name"`
	Label    string      `xml:"label"`
	MetaData KVMMetaData `xml:"metadata"`
	Devices  KVMDevices  `xml:"devices"`
}
type KVMDomains struct {
	Domains []KVMDomain `xml:"domain"`
}

type XMLVPC struct {
	UUID string
	Name string
}

type XMLInterface struct {
	Mac    string
	Target string
}

type XMLVM struct {
	UUID       string
	Name       string
	Label      string
	VPC        XMLVPC
	Interfaces []XMLInterface
}

type scrapeConfig struct {
	JobName     string `yaml:"job_name"`
	HonorLabels bool   `yaml:"honor_labels"`
}

type prometheusConfig struct {
	ScrapeConfigs []scrapeConfig `yaml:"scrape_configs"`
}

var IfaceRegex = regexp.MustCompile("^(\\d+):\\s+([^@:]+)(@.*)?\\:")
var MACRegex = regexp.MustCompile("^\\s+link/\\S+\\s+(([\\dA-Za-z]{2}:){5}[\\dA-Za-z]{2}) brd.*$")
var IPRegex = regexp.MustCompile("^\\s+inet6?\\s+([\\d\\.A-Za-z:]+)/(\\d+)\\s+.*scope\\s+(global|link|host)")

func ParseIPOutput(s string) ([]Iface, error) {
	ifaces := []Iface{}
	if s == "" {
		return ifaces, nil
	}
	iface := Iface{Index: -1}
	lines := strings.Split(s, "\n")
	if len(lines) == 1 && lines[0] == "" {
		return ifaces, nil
	}
	for _, line := range lines {
		ifaceMatched := IfaceRegex.FindStringSubmatch(line)
		if ifaceMatched != nil {
			if iface.Index != -1 {
				ifaces = append(ifaces, iface)
				iface = Iface{}
			}
			index, err := strconv.Atoi(ifaceMatched[1])
			if err != nil {
				return []Iface{}, err
			}
			iface.Index = index
			iface.Name = ifaceMatched[2]
			if ifaceMatched[3] != "" {
				iface.Peer = ifaceMatched[3][1:]
			}
			if iface.Peer != "" && strings.HasPrefix(iface.Peer, "if") {
				peerIndex, err := strconv.Atoi(iface.Peer[2:])
				if err != nil {
					return []Iface{}, err
				}
				iface.PeerIndex = peerIndex
			}
		}

		macMatched := MACRegex.FindStringSubmatch(line)
		if macMatched != nil {
			iface.MAC = macMatched[1]
		} else if strings.HasPrefix(iface.Name, "tunl0") {
			iface.MAC = "00:00:00:00:00:00"
		}
		ipMatched := IPRegex.FindStringSubmatch(line)
		if ipMatched != nil {
			maskLen, err := strconv.Atoi(ipMatched[2])
			if err != nil {
				return []Iface{}, err
			}
			iface.IPs = append(iface.IPs, VifInfo{
				Address: ipMatched[1],
				Scope:   ipMatched[3],
				MaskLen: uint32(maskLen),
			})
		}
	}
	ifaces = append(ifaces, iface)
	return ifaces, nil
}

func ParseCSV(s string, fields ...string) ([]map[string]string, error) {
	ret := []map[string]string{}
	if s == "" {
		return ret, nil
	}
	sReader := strings.NewReader(s)
	csvReader := csv.NewReader(sReader)
	csvs, err := csvReader.ReadAll()
	if err != nil {
		return ret, err
	}
	for _, c := range csvs[1:] {
		item := map[string]string{}
		for i, name := range csvs[0] {
			sort.Strings(fields)
			index := sort.SearchStrings(fields, name)
			if len(fields) > 0 && !(index < len(fields) && fields[index] == name) {
				continue
			}
			item[name] = c[i]
		}
		ret = append(ret, item)
	}
	return ret, nil
}

func ParseCSVWithKey(s, key string, fields ...string) (map[string]map[string]string, error) {
	ret := map[string]map[string]string{}
	if s == "" {
		return ret, nil
	}
	sReader := strings.NewReader(s)
	csvReader := csv.NewReader(sReader)
	csvs, err := csvReader.ReadAll()
	if err != nil {
		return ret, err
	}
	for _, c := range csvs[1:] {
		item := map[string]string{}
		k := ""
		for i, name := range csvs[0] {
			if name == key {
				k = c[i]
			}
			sort.Strings(fields)
			index := sort.SearchStrings(fields, name)
			if len(fields) > 0 && !(index < len(fields) && fields[index] == name) {
				continue
			}
			item[name] = c[i]
		}
		if k != "" {
			ret[k] = item
		}
	}
	return ret, nil
}

func ParseKVString(s string) (map[string]string, error) {
	options := map[string]string{}
	trimString := strings.Trim(s, " ")
	kvSlice := strings.Split(trimString, " ")
	for _, kvString := range kvSlice {
		kv := strings.Split(kvString, "=")
		if len(kv) == 1 {
			kv = append(kv, "")
		}
		options[kv[0]] = kv[1]
	}
	return options, nil
}

func ParseBrctlShow(s string) (map[string][]string, error) {
	brs := map[string][]string{}
	lines := strings.Split(s, "\n")
	if len(lines) <= 1 {
		return brs, nil
	}
	lastBr := ""
	for _, line := range lines[1:] {
		cols := strings.Split(line, "\t")
		brName := cols[0]
		ifName := cols[len(cols)-1]
		if brName != "" {
			lastBr = brName
			brs[brName] = []string{}
		}
		if ifName != "" {
			brs[lastBr] = append(brs[lastBr], ifName)
		}
	}
	return brs, nil
}

func ParseVLANConfig(s string) (map[string]int, error) {
	configs := map[string]int{}
	lines := strings.Split(s, "\n")
	if len(lines) <= 2 {
		return configs, nil
	}
	for _, line := range lines[2:] {
		cols := strings.Split(line, "|")
		if len(cols) != 3 {
			continue
		}
		vlanID, err := strconv.Atoi(strings.Trim(cols[1], " "))
		if err != nil {
			return configs, err
		}
		configs[strings.Trim(cols[0], " ")] = vlanID
	}
	return configs, nil
}

func ParseVMStates(s string) (map[string]int, error) {
	vmToState := map[string]int{}
	lines := strings.Split(s, "\n")
	if len(lines) <= 2 {
		return vmToState, nil
	}
	for _, line := range lines[2:] {
		fields := strings.Fields(line)
		if len(fields) != 3 && len(fields) != 4 {
			continue
		}
		name := strings.Trim(fields[1], " ")
		stateStr := strings.Trim(fields[2], " ")
		var state int
		switch stateStr {
		case "running":
			state = common.VM_STATE_RUNNING
		case "shut", "关闭":
			state = common.VM_STATE_STOPPED
		default:
			state = common.VM_STATE_EXCEPTION
		}
		vmToState[name] = state
	}
	return vmToState, nil
}

func ParseVMXml(s string) ([]XMLVM, error) {
	var vms []XMLVM
	if s == "" {
		return vms, nil
	}

	// ns := "http://openstack.org/xmlns/libvirt/nova/1.0"

	var domains KVMDomains
	err := xml.Unmarshal([]byte(s), &domains)
	if err != nil {
		return vms, err
	}
	for _, domain := range domains.Domains {
		var vm XMLVM
		if domain.UUID == "" {
			continue
		}
		vm.UUID = domain.UUID
		if domain.Name == "" {
			continue
		}
		vm.Label = domain.Name
		vm.Name = domain.MetaData.Instance.Name
		if vm.Name == "" {
			vm.Name = vm.Label
		}
		if domain.MetaData.Instance.Owner.Project.UUID != "" {
			uuid := domain.MetaData.Instance.Owner.Project.UUID
			if len(uuid) == 32 {
				uuid = strings.Join([]string{uuid[:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:]}, "-")
			}
			vm.VPC = XMLVPC{
				UUID: uuid,
				Name: domain.MetaData.Instance.Owner.Project.Value,
			}
		}
		if len(domain.Devices.Interfaces) != 0 {
			var interfaces []XMLInterface
			for _, item := range domain.Devices.Interfaces {
				var iface XMLInterface
				iface.Target = item.Target.Value
				iface.Mac = item.Mac.Value
				interfaces = append(interfaces, iface)
			}
			vm.Interfaces = interfaces
		}
		vms = append(vms, vm)
	}
	return vms, nil
}

func ParseYMAL(y string) (prometheusConfig, error) {
	pConfig := prometheusConfig{}
	err := yaml.Unmarshal([]byte(y), &pConfig)
	if err != nil {
		return prometheusConfig{}, err
	}
	return pConfig, nil
}

func ParseCompressedInfo(cInfo []byte) (bytes.Buffer, error) {
	reader := bytes.NewReader(cInfo)
	var out bytes.Buffer
	r, err := zlib.NewReader(reader)
	if err != nil {
		return bytes.Buffer{}, err
	}
	_, err = out.ReadFrom(r)
	if err != nil {
		return bytes.Buffer{}, err
	}
	return out, nil
}

func Uint64ToMac(v uint64) net.HardwareAddr {
	bytes := [8]byte{}
	BigEndian.PutUint64(bytes[:], v)
	return net.HardwareAddr(bytes[2:])
}

func IPInRanges(ip string, ipRanges ...netaddr.IPPrefix) bool {
	ipObj, err := netaddr.ParseIP(ip)
	if err != nil {
		return false
	}
	for _, ipRange := range ipRanges {
		if ipRange.Contains(ipObj) {
			return true
		}
	}
	return false
}
