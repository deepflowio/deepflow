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
	"bufio"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"inet.af/netaddr"

	"github.com/bitly/go-simplejson"
	mapset "github.com/deckarep/golang-set"
	"github.com/mikioh/ipaddr"
	logging "github.com/op/go-logging"
	uuid "github.com/satori/go.uuid"

	"github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/genesis"
	controllermodel "github.com/deepflowio/deepflow/server/controller/model"
)

var log = logging.MustGetLogger("cloud.common")

func StringStringMapKeys(m map[string]string) (keys []string) {
	for k := range m {
		keys = append(keys, k)
	}
	return
}

func StringInterfaceMapKeys(m map[string]interface{}) (keys []string) {
	for k := range m {
		keys = append(keys, k)
	}
	return
}

func StringInterfaceMapKVs(m map[string]interface{}, sep string, valueMaxLength int) (items []string) {
	keys := []string{}
	for key := range m {
		value, ok := m[key].(string)
		if !ok {
			value = ""
		}
		if valueMaxLength != 0 && len(value) > valueMaxLength {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, ok := m[k].(string)
		if !ok {
			v = ""
		}
		newString := k + sep + v
		items = append(items, newString)
	}
	return
}

func StringSliceStringMapKeys(m map[string][]string) (keys []string) {
	for k := range m {
		keys = append(keys, k)
	}
	return
}

func StringStringMapValues(m map[string]string) (values []string) {
	for k := range m {
		values = append(values, m[k])
	}
	return
}

func UnionMapStringInt(m, n map[string]int) map[string]int {
	for k, v := range n {
		m[k] = v
	}
	return m
}

func UnionMapStringString(m, n map[string]string) map[string]string {
	for k, v := range n {
		m[k] = v
	}
	return m
}

func UnionMapStringSet(m, n map[string]mapset.Set) map[string]mapset.Set {
	for k, v := range n {
		if _, ok := m[k]; !ok {
			m[k] = v
		} else {
			m[k] = m[k].Union(v)
		}
	}
	return m
}

func ReadJSONFile(path string) (*simplejson.Json, error) {
	jsonFile, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read json file error:" + err.Error())
	}
	js, err := simplejson.NewJson([]byte(jsonFile))

	if err != nil {
		return nil, errors.New("initialization simplejson error:" + err.Error())
	}
	return js, nil
}

func ReadLineJSONFile(path string) (js []*simplejson.Json, err error) {
	jsFile, oErr := os.Open(path)
	defer jsFile.Close()
	if oErr != nil {
		err = oErr
		return
	}
	buf := bufio.NewReader(jsFile)
	for {
		lineFile, _, eof := buf.ReadLine()
		if eof == io.EOF {
			break
		}
		lineJs, sErr := simplejson.NewJson(lineFile)
		if sErr != nil {
			err = sErr
			return
		}
		js = append(js, lineJs)
	}
	return
}

func GenerateIPMask(ip string) int {
	netO, err := netaddr.ParseIPPrefix(ip)
	if err == nil {
		maskLen, _ := netO.IPNet().Mask.Size()
		return maskLen
	}
	if strings.Contains(ip, ":") {
		return common.IPV6_MAX_MASK
	}
	return common.IPV4_MAX_MASK
}

func IPAndMaskToCIDR(ip string, mask int) (string, error) {
	ipO, err := netaddr.ParseIP(ip)
	if err != nil {
		return "", errors.New("ip and mask to cidr ip format error:" + err.Error())
	}
	IPString := ipO.String() + "/" + strconv.Itoa(mask)
	netO, err := netaddr.ParseIPPrefix(IPString)
	if err != nil {
		return "", errors.New("ip and mask to cidr format error" + err.Error())
	}
	netRange, ok := netO.Range().Prefix()
	if !ok {
		return "", errors.New("ip and mask to cidr format not valid")
	}
	return netRange.String(), nil
}

func TidyIPString(ipsString []string) (v4Prefix, v6Prefix []netaddr.IPPrefix, err error) {
	for _, ipS := range ipsString {
		_, ignoreErr := netaddr.ParseIPPrefix(ipS)
		if ignoreErr != nil {
			switch {
			case strings.Contains(ipS, "."):
				ipS = ipS + "/32"
			case strings.Contains(ipS, ":"):
				ipS = ipS + "/128"
			}
		}
		ipPrefix, prefixErr := netaddr.ParseIPPrefix(ipS)
		if prefixErr != nil {
			err = prefixErr
			return
		}
		switch {
		case ipPrefix.IP().Is4():
			v4Prefix = append(v4Prefix, ipPrefix)
		case ipPrefix.IP().Is6():
			v6Prefix = append(v6Prefix, ipPrefix)
		}
	}
	return
}

func AggregateCIDR(ips []netaddr.IPPrefix, maxMask int) (cirdsString []string) {
	CIDRs := []*ipaddr.Prefix{}
	for _, Prefix := range ips {
		aggFlag := false
		ipNet := ipaddr.NewPrefix(Prefix.IPNet())
		for i, CIDR := range CIDRs {
			pSlice := []ipaddr.Prefix{*ipNet, *CIDR}
			aggCIDR := ipaddr.Supernet(pSlice)
			if aggCIDR == nil {
				continue
			}
			aggCIDRMask, _ := aggCIDR.IPNet.Mask.Size()
			if aggCIDRMask >= maxMask {
				CIDRs[i] = aggCIDR
				aggFlag = true
				break
			} else {
				continue
			}
		}
		if !aggFlag {
			CIDRs = append(CIDRs, ipNet)
		}
	}
	for _, i := range CIDRs {
		cirdsString = append(cirdsString, i.String())
	}
	return
}

func GenerateCIDR(ips []netaddr.IPPrefix, maxMask int) (cirds []netaddr.IPPrefix) {
	CIDRs := []*ipaddr.Prefix{}
	for _, Prefix := range ips {
		aggFlag := false
		ipNet := ipaddr.NewPrefix(Prefix.IPNet())
		for i, CIDR := range CIDRs {
			if CIDR.Contains(ipNet) {
				aggFlag = true
				break
			}
			pSlice := []ipaddr.Prefix{*ipNet, *CIDR}
			aggCIDR := ipaddr.Supernet(pSlice)
			if aggCIDR == nil {
				continue
			}
			aggCIDRMask, _ := aggCIDR.IPNet.Mask.Size()
			if aggCIDRMask >= maxMask {
				CIDRs[i] = aggCIDR
				aggFlag = true
				break
			} else {
				continue
			}
		}
		if !aggFlag {
			CIDRs = append(CIDRs, ipNet)
		}
	}
	for _, i := range CIDRs {
		cirds = append(cirds, netaddr.MustParseIPPrefix(i.String()))
	}
	return
}

func IsIPInCIDR(ip, cidr string) bool {
	if strings.Contains(cidr, "/") {
		_, nCIDR, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Errorf("parse cidr failed: %v", err)
			return false
		}
		return nCIDR.Contains(net.ParseIP(ip))
	} else {
		if ip == cidr {
			return true
		}
		return false
	}
}

func ContainsIP(cidrs []string, ip string) bool {
	if len(cidrs) == 0 {
		return false
	}
	for _, cidr := range cidrs {
		if IsIPInCIDR(ip, cidr) {
			return true
		}
	}
	return false
}

// 针对各私有云平台，每个区域生成一个基础VPC和子网
// 宿主机及管理节点的接口和IP属于基础VPC和子网
func GetBasicVPCLcuuid(uuidGenerate, regionLcuuid string) string {
	return common.GenerateUUID(uuidGenerate + regionLcuuid)
}

func GetBasicNetworkLcuuid(vpcLcuuid string) string {
	return common.GenerateUUID(vpcLcuuid)
}

func GetBasicVPCAndNetworks(regions []model.Region, regionLcuuid, domainName, uuidGenerate string) ([]model.VPC, []model.Network) {
	var retVPCs []model.VPC
	var retNetworks []model.Network

	// 没有有效区域时, 根据 regionLcuuid 生成一个参考区域
	if len(regions) == 0 && regionLcuuid != "" {
		regions = append(regions, model.Region{
			Name:   "",
			Lcuuid: regionLcuuid,
		})
	}

	for _, region := range regions {
		vpcLcuuid := GetBasicVPCLcuuid(uuidGenerate, region.Lcuuid)
		vpcName := domainName + fmt.Sprintf("%s_基础VPC_%s", domainName, region.Name)
		retVPCs = append(retVPCs, model.VPC{
			Lcuuid:       vpcLcuuid,
			Name:         vpcName,
			RegionLcuuid: region.Lcuuid,
		})
		retNetworks = append(retNetworks, model.Network{
			Lcuuid:         GetBasicNetworkLcuuid(vpcLcuuid),
			Name:           vpcName + "子网",
			SegmentationID: 1,
			NetType:        common.NETWORK_TYPE_LAN,
			VPCLcuuid:      vpcLcuuid,
			RegionLcuuid:   region.Lcuuid,
		})
	}

	return retVPCs, retNetworks
}

// 根据采集器上报的接口信息，生成宿主机的接口和IP信息
func GetHostNics(hosts []model.Host, domainName, uuidGenerate, portNameRegex string, excludeIPs []string) (
	[]model.Subnet, []model.VInterface, []model.IP, map[string][]model.Subnet, error,
) {
	var retSubnets []model.Subnet
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	vtaps := []mysql.VTap{}
	mysql.Db.Find(&vtaps)

	vtapLaunchServerToCtrlIP := make(map[string]string)
	for _, vtap := range vtaps {
		vtapLaunchServerToCtrlIP[vtap.LaunchServer] = vtap.CtrlIP
	}

	if genesis.GenesisService == nil {
		return []model.Subnet{}, []model.VInterface{}, []model.IP{}, map[string][]model.Subnet{}, errors.New("genesis service is nil")
	}
	genesisData, err := genesis.GenesisService.GetGenesisSyncResponse()
	if err != nil {
		return []model.Subnet{}, []model.VInterface{}, []model.IP{}, map[string][]model.Subnet{}, err
	}
	vDatas := genesisData.Vinterfaces
	hostIPToVInterfaces := map[string][]controllermodel.GenesisVinterface{}
	for _, vData := range vDatas {
		if vData.DeviceType != "kvm-host" {
			continue
		}
		hostIPToVInterfaces[vData.HostIP] = append(hostIPToVInterfaces[vData.HostIP], vData)
	}

	var reg *regexp.Regexp
	if portNameRegex != "" {
		reg, err = regexp.Compile(portNameRegex)
		if err != nil {
			return []model.Subnet{}, []model.VInterface{}, []model.IP{}, map[string][]model.Subnet{}, err
		}
	}
	// 遍历宿主机生成网段、接口和IP信息
	vpcLcuuidToSubnets := make(map[string][]model.Subnet)
	for _, host := range hosts {
		vtapCtrlIP, ok := vtapLaunchServerToCtrlIP[host.IP]
		if !ok {
			log.Debugf("no vtap with launch_server (%s)", host.IP)
			continue
		}
		vinterfaces, ok := hostIPToVInterfaces[vtapCtrlIP]
		if !ok {
			log.Debugf("no host (%s) vinterfaces in response", host.IP)
			continue
		}
		vpcLcuuid := GetBasicVPCLcuuid(uuidGenerate, host.RegionLcuuid)
		networkLcuuid := GetBasicNetworkLcuuid(vpcLcuuid)
		subnets, ok := vpcLcuuidToSubnets[vpcLcuuid]
		if !ok {
			subnets = []model.Subnet{}
		}

		// 遍历采集器上报的宿主机接口列表
		// 额外对接路由接口为空 或者 不匹配额外对接路由接口时，跳过该接口
		includeHostIP := false
		for _, vinterface := range vinterfaces {
			if reg == nil || !reg.MatchString(vinterface.Name) {
				log.Debugf("vinterface name (%s) reg (%s) not match", vinterface.Name, portNameRegex)
				continue
			}

			if vinterface.IPs == "" {
				log.Debugf("vinterface name (%s) not found ips", vinterface.Name)
				continue
			}

			vinterfaceLcuuid := common.GenerateUUID(host.Lcuuid + vinterface.Mac)
			ips := strings.Split(vinterface.IPs, ",")
			for _, ip := range ips {
				subnetLcuuid := ""
				ipMasks := strings.Split(ip, "/")
				if ipMasks[0] == host.IP {
					includeHostIP = true
				}
				ipAddr := netaddr.IP{}
				ipMask := strconv.Itoa(common.IPV4_MAX_MASK)
				if strings.Contains(ip, ":") {
					ipMask = strconv.Itoa(common.IPV6_MAX_MASK)
				}
				if len(ipMasks) > 1 {
					ipAddr, err = netaddr.ParseIP(ipMasks[0])
					if err != nil {
						log.Debugf("parse ip (%s) failed", ipMasks[0])
						continue
					}
					ipMask = ipMasks[1]
				}
				// 判断是否在excludeIPs；如果是，则跳过
				IsExcludeIP := false
				for _, excludeIP := range excludeIPs {
					if IsIPInCIDR(ipMasks[0], excludeIP) {
						IsExcludeIP = true
						break
					}
				}
				if IsExcludeIP {
					continue
				}

				// 判断IP + 掩码信息是否已经在当前网段中；如果不在，则生成新的网段信息
				for _, subnet := range subnets {
					subnetCidr, err := netaddr.ParseIPPrefix(subnet.CIDR)
					if err != nil {
						log.Debugf("parse ip prefix (%s) failed", subnet.CIDR)
						continue
					}
					if subnetCidr.Contains(ipAddr) {
						subnetLcuuid = subnet.Lcuuid
						break
					}
				}
				if subnetLcuuid == "" {
					cidrParse, err := ipaddr.Parse(ip)
					if err != nil {
						log.Debugf("parse ip (%s) failed", ip)
						continue
					}
					subnetCidr := cidrParse.First().IP.String() + "/" + ipMask
					subnetLcuuid = common.GenerateUUID(networkLcuuid + subnetCidr)
					retSubnet := model.Subnet{
						Lcuuid:        subnetLcuuid,
						Name:          subnetCidr,
						CIDR:          subnetCidr,
						NetworkLcuuid: networkLcuuid,
						VPCLcuuid:     vpcLcuuid,
					}
					retSubnets = append(retSubnets, retSubnet)
					vpcLcuuidToSubnets[vpcLcuuid] = append(
						vpcLcuuidToSubnets[vpcLcuuid], retSubnet,
					)
				}

				// 增加IP信息
				retIPs = append(retIPs, model.IP{
					Lcuuid:           common.GenerateUUID(vinterfaceLcuuid + ipMasks[0]),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               ipMasks[0],
					SubnetLcuuid:     subnetLcuuid,
					RegionLcuuid:     host.RegionLcuuid,
				})
			}
			// 增加接口信息
			retVInterfaces = append(retVInterfaces, model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				NetnsID:       vinterface.NetnsID,
				VTapID:        vinterface.VtapID,
				Type:          common.VIF_TYPE_LAN,
				Mac:           vinterface.Mac,
				DeviceType:    common.VIF_DEVICE_TYPE_HOST,
				DeviceLcuuid:  host.Lcuuid,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  host.RegionLcuuid,
			})
		}

		// 如果vinterface中没有返回hostIP，则使用全0的MAC生成接口和IP信息
		if includeHostIP {
			continue
		}
		// 判断IP是否已经在当前网段中；如果不在，则生成新的网段信息
		ipAddr, err := netaddr.ParseIP(host.IP)
		if err != nil {
			log.Debugf("parse ip (%s) failed", host.IP)
			continue
		}
		subnetLcuuid := ""
		for _, subnet := range subnets {
			subnetCidr, err := netaddr.ParseIPPrefix(subnet.CIDR)
			if err != nil {
				log.Debugf("parse ip prefix (%s) failed", subnet.CIDR)
				continue
			}
			if subnetCidr.Contains(ipAddr) {
				subnetLcuuid = subnet.Lcuuid
				break
			}
		}
		if subnetLcuuid == "" {
			ipMask := strconv.Itoa(common.IPV4_DEFAULT_NETMASK)
			if strings.Contains(host.IP, ":") {
				ipMask = strconv.Itoa(common.IPV6_DEFAULT_NETMASK)
			}
			cidrParse, err := ipaddr.Parse(host.IP + "/" + ipMask)
			if err != nil {
				log.Debugf("parse ip (%s) failed", host.IP+"/"+ipMask)
				continue
			}
			subnetCidr := cidrParse.First().IP.String() + "/" + ipMask
			subnetLcuuid = common.GenerateUUID(networkLcuuid + subnetCidr)
			retSubnet := model.Subnet{
				Lcuuid:        subnetLcuuid,
				Name:          subnetCidr,
				CIDR:          subnetCidr,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
			}
			retSubnets = append(retSubnets, retSubnet)
			vpcLcuuidToSubnets[vpcLcuuid] = append(
				vpcLcuuidToSubnets[vpcLcuuid], retSubnet,
			)
		}

		// 增加接口和IP信息
		mac := common.VIF_DEFAULT_MAC
		vinterfaceLcuuid := common.GenerateUUID(host.Lcuuid + mac)
		retVInterfaces = append(retVInterfaces, model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          common.VIF_TYPE_LAN,
			Mac:           mac,
			DeviceType:    common.VIF_DEVICE_TYPE_HOST,
			DeviceLcuuid:  host.Lcuuid,
			NetworkLcuuid: networkLcuuid,
			VPCLcuuid:     vpcLcuuid,
			RegionLcuuid:  host.RegionLcuuid,
		})
		retIPs = append(retIPs, model.IP{
			Lcuuid:           common.GenerateUUID(vinterfaceLcuuid + host.IP),
			VInterfaceLcuuid: vinterfaceLcuuid,
			IP:               host.IP,
			SubnetLcuuid:     subnetLcuuid,
			RegionLcuuid:     host.RegionLcuuid,
		})
	}

	return retSubnets, retVInterfaces, retIPs, vpcLcuuidToSubnets, nil
}

func EliminateEmptyRegions(regions []model.Region, regionLcuuidToResourceNum map[string]int) []model.Region {
	var retRegions []model.Region

	for _, region := range regions {
		resourceNum := 0
		resourceNum, ok := regionLcuuidToResourceNum[region.Lcuuid]
		if !ok || resourceNum == 0 {
			continue
		}
		retRegions = append(retRegions, region)
	}
	return retRegions
}

func EliminateEmptyAZs(azs []model.AZ, azLcuuidToResourceNum map[string]int) []model.AZ {
	var retAZs []model.AZ

	for _, az := range azs {
		resourceNum := 0
		resourceNum, ok := azLcuuidToResourceNum[az.Lcuuid]
		if !ok || resourceNum == 0 {
			continue
		}
		retAZs = append(retAZs, az)
	}
	return retAZs
}

// 根据主机名获取主机IP
// 不同方式优先级：DNS > file > Hash
func GetHostIPByName(name string) (string, error) {
	ip, err := getHostIPFromDNS(name)
	if ip != "" || err != nil {
		return ip, err
	}
	ip, err = getHostIPFromFile(name)
	if ip != "" || err != nil {
		return ip, err
	}
	return createHostIPFromHash(name), nil
}

func getHostIPFromDNS(name string) (string, error) {
	if config.CONF.DNSEnable {
		ips, err := net.LookupIP(name) // TODO 是否需要自定义err
		if err == nil {
			return ips[0].String(), err
		} else {
			log.Errorf("lookup for hostname: %s failed: %v", name, err)
		}
	}
	return "", nil
}

func getHostIPFromFile(name string) (string, error) {
	// TODO 将此文件内容持久化，避免每次都重新读取
	f, err := os.Open(config.CONF.HostnameToIPFile)
	if err == nil {
		defer f.Close()

		csvReader := csv.NewReader(f)
		lines, err := csvReader.ReadAll()
		if err == nil {
			for _, line := range lines {
				if len(line) != 2 {
					continue
				}
				if line[0] == name {
					return line[1], nil
				}
			}
		} else {
			log.Errorf("read file: %s failed: %v", config.CONF.HostnameToIPFile, err)
		}
	} else {
		log.Errorf("open file: %s failed: %v", config.CONF.HostnameToIPFile, err)
	}
	return "", nil
}

func createHostIPFromHash(name string) string {
	return InetNToA(BKDRHash(name))
}

func BKDRHash(str string) uint32 {
	var h uint32
	seed := uint32(131)
	for _, c := range str {
		h = h*seed + uint32(c)
	}
	return h
}

func InetNToA(ip uint32) string {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, ip)
	return fmt.Sprintf("%d.%d.%d.%d", data[3], data[2], data[1], data[0])
}

func GetAZLcuuidFromUUIDGenerate(uuidGenerate string) string {
	lcuuid := common.GetUUID(uuidGenerate, uuid.Nil)
	return lcuuid[:len(lcuuid)-2] + "ff"
}

// TODO add reason
func GenerateWANVInterfaceMac(mac string) string {
	if len(mac) < 2 {
		log.Errorf("generate mac: %s failed", mac)
		return mac
	}
	return "ff" + mac[2:]
}

func DiffMap(base, another map[string]string) bool {
	for k, v := range another {
		bValue, ok := base[k]
		if !ok {
			return true
		}
		if v != bValue {
			return true
		}
	}
	return false
}

func GetVTapSubDomainMappingByDomain(domain string) (map[int]string, error) {
	vtapIDToSubDomain := make(map[int]string)

	var azs []mysql.AZ
	err := mysql.Db.Where("domain = ?", domain).Find(&azs).Error
	if err != nil {
		return vtapIDToSubDomain, err
	}
	azLcuuids := []string{}
	for _, az := range azs {
		azLcuuids = append(azLcuuids, az.Lcuuid)
	}

	var podNodes []mysql.PodNode
	err = mysql.Db.Where("domain = ?", domain).Find(&podNodes).Error
	if err != nil {
		return vtapIDToSubDomain, err
	}
	podNodeIDToSubDomain := make(map[int]string)
	for _, podNode := range podNodes {
		podNodeIDToSubDomain[podNode.ID] = podNode.SubDomain
	}

	var pods []mysql.Pod
	err = mysql.Db.Where("domain = ?", domain).Find(&pods).Error
	if err != nil {
		return vtapIDToSubDomain, err
	}
	podIDToSubDomain := make(map[int]string)
	for _, pod := range pods {
		podIDToSubDomain[pod.ID] = pod.SubDomain
	}

	var vtaps []mysql.VTap
	err = mysql.Db.Where("az IN ?", azLcuuids).Find(&vtaps).Error
	if err != nil {
		return vtapIDToSubDomain, err
	}
	for _, vtap := range vtaps {
		vtapIDToSubDomain[vtap.ID] = ""
		if vtap.Type == common.VTAP_TYPE_POD_HOST || vtap.Type == common.VTAP_TYPE_POD_VM {
			if subDomain, ok := podNodeIDToSubDomain[vtap.LaunchServerID]; ok {
				vtapIDToSubDomain[vtap.ID] = subDomain
			}
		} else if vtap.Type == common.VTAP_TYPE_K8S_SIDECAR {
			if subDomain, ok := podIDToSubDomain[vtap.LaunchServerID]; ok {
				vtapIDToSubDomain[vtap.ID] = subDomain
			}
		}
	}

	return vtapIDToSubDomain, nil
}
