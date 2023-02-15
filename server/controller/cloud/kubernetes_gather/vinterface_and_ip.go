/*
 * Copyright (c) 2022 Yunshan Networks
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

package kubernetes_gather

import (
	"errors"
	"inet.af/netaddr"
	"regexp"
	"sort"
	"strings"

	mapset "github.com/deckarep/golang-set"
	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/genesis"
	"github.com/mikioh/ipaddr"
	uuid "github.com/satori/go.uuid"
)

func (k *KubernetesGather) getVInterfacesAndIPs() (nodeSubnets, podSubnets []model.Subnet, nodeVInterfaces, podVInterfaces []model.VInterface, nodeIPs, podIPs []model.IP, err error) {
	log.Debug("get vinterfaces,ips starting")
	hostIPToNodeIPs := map[string][]string{}
	deviceUUIDToPodLcuuid := map[string]string{}
	vinterfaceLcuuids := mapset.NewSet()
	subnetLcuuidToCIDR := map[string]netaddr.IPPrefix{}
	ipToVinterfaceLcuuid := map[string]string{}
	podIPsMap := map[string]*model.IP{}
	aggNoMaskV4Nets := []string{}
	aggNoMaskV6Nets := []string{}
	noMaskPodV4CIDRs := []*ipaddr.Prefix{}
	noMaskPodV6CIDRs := []*ipaddr.Prefix{}
	k8sNodeIPs := mapset.NewSet()
	for key := range k.nodeIPToLcuuid {
		k8sNodeIPs.Add(key)
	}

	portNameRegex, err := regexp.Compile(k.PortNameRegex)
	if err != nil {
		log.Errorf("config port name regex (%s) complie failed", k.PortNameRegex)
		return
	}

	// 获取vinterface API返回中host ip与其上所有node ip的对应关系
	if genesis.GenesisService == nil {
		err = errors.New("genesis service is nil")
		return
	}
	genesisData, err := genesis.GenesisService.GetGenesisSyncResponse()
	if err != nil {
		log.Error("get genesis vinterface failed")
		return
	}
	vData := genesisData.Vinterfaces
	for _, vItem := range vData {
		if vItem.KubernetesClusterID != k.ClusterID {
			continue
		}
		deviceType := vItem.DeviceType
		if deviceType == "docker-host" || deviceType == "kvm-host" {
			nIPs := []string{}
			IPSlice := strings.Split(vItem.IPs, ",")
			for _, j := range IPSlice {
				if j == "" {
					continue
				}
				vIP := strings.Split(j, "/")[0]
				nIPs = append(nIPs, vIP)
			}
			hostIP := vItem.HostIP
			_, ok := hostIPToNodeIPs[hostIP]
			if ok {
				hostIPToNodeIPs[hostIP] = append(hostIPToNodeIPs[hostIP], nIPs...)
			} else {
				hostIPToNodeIPs[hostIP] = nIPs
			}
		}
	}
	// 生成device_uuid或uuid和pod lcuuid的对应关系
	for _, vItem := range vData {
		if vItem.KubernetesClusterID != k.ClusterID {
			continue
		}
		if vItem.DeviceType != "docker-container" {
			continue
		}
		vIPs := strings.Split(vItem.IPs, ",")
		podLcuuid := ""
		for _, j := range vIPs {
			if j == "" {
				continue
			}
			vIP := strings.Split(j, "/")[0]
			if vlcuuid, ok := k.podIPToLcuuid[vIP]; ok {
				podLcuuid = vlcuuid
				delete(k.podIPToLcuuid, vIP)
				break
			}
		}
		if podLcuuid == "" {
			continue
		}

		// genesis上报的资源优先使用device_uuid
		// 如果没有device_uuid则使用uuid
		// trident有权限拿到网卡ip的掩码的时候，uuid和device_uuid是相同的，否则不同
		deviceUUID := vItem.DeviceLcuuid
		if deviceUUID != "" {
			deviceUUIDToPodLcuuid[deviceUUID] = podLcuuid
		} else {
			vUUID := vItem.Lcuuid
			if vUUID == "" {
				continue
			}
			deviceUUIDToPodLcuuid[vUUID] = podLcuuid
		}
	}

	podSubnetLcuuid := ""
	if len(k.podNetworkLcuuidCIDRs.cidrs) == 1 {
		podSubnetLcuuid = common.GetUUID(k.podNetworkLcuuidCIDRs.networkLcuuid, uuid.Nil)
	}
	// 处理POD IP，生成port，ip，cidrs信息
	for _, vItem := range vData {
		if vItem.KubernetesClusterID != k.ClusterID {
			continue
		}
		if vItem.DeviceType != "docker-container" {
			continue
		}
		deviceUUID := vItem.DeviceLcuuid
		vMAC := vItem.Mac
		vTAPMAC := vItem.TapMac
		podLcuuid := deviceUUIDToPodLcuuid[deviceUUID]
		if podLcuuid == "" {
			vUUID := vItem.Lcuuid
			podLcuuid = deviceUUIDToPodLcuuid[vUUID]
		}
		if podLcuuid == "" {
			log.Debugf("vinterface,ip port (%s) pod not found", vMAC)
			continue
		}

		vinterfaceLcuuid := common.GetUUID(podLcuuid+vMAC, uuid.Nil)
		if !vinterfaceLcuuids.Contains(vinterfaceLcuuid) {
			vinterfaceLcuuids.Add(vinterfaceLcuuid)
			vinterface := model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          common.VIF_TYPE_LAN,
				Mac:           vMAC,
				TapMac:        vTAPMAC,
				DeviceType:    common.VIF_DEVICE_TYPE_POD,
				DeviceLcuuid:  podLcuuid,
				NetworkLcuuid: k.podNetworkLcuuidCIDRs.networkLcuuid,
				VPCLcuuid:     k.VPCUuid,
				RegionLcuuid:  k.RegionUuid,
			}
			podVInterfaces = append(podVInterfaces, vinterface)
		}
		vIPs := strings.Split(vItem.IPs, ",")
		// 判断是否在POD默认cidr中，如果在则使用该cidr
		// 判断IP/网段是否已有其他cidr中，如果在则使用该cidr
		// 否则
		//   如果是IP或者地址为32/128位掩码，则判断是否生成新的NO_MASK cidr
		// 	 cidr超出限定的掩码，则生成新的cidr
		// 	 cidr不超出限定的掩码，则更新已有cidr
		//   如果是网段，则基于该网段生成新的cidr
		for _, ipString := range vIPs {
			ipPrefix, err := netaddr.ParseIPPrefix(ipString)
			if err != nil {
				switch {
				case strings.Contains(ipString, "."):
					ipString = ipString + "/32"
				case strings.Contains(ipString, ":"):
					ipString = ipString + "/128"
				}
			}
			ipPrefix, err = netaddr.ParseIPPrefix(ipString)
			if err != nil {
				log.Errorf("vinterface,ip parse cidrs (%s) error: (%s)", ipString, err.Error())
				continue
			}
			ip := ipPrefix.IP()
			ipMask, _ := ipPrefix.IPNet().Mask.Size()
			ipLcuuid := common.GetUUID(vinterfaceLcuuid+ip.String(), uuid.Nil)
			subnetLcuuid := ""
			for _, podNetworkCIDR := range k.podNetworkLcuuidCIDRs.cidrs {
				netPrefix, err := netaddr.ParseIPPrefix(podNetworkCIDR)
				if err != nil {
					log.Errorf("vinterface,ip parse cidr (%s) error: (%s)", podNetworkCIDR, err.Error())
					continue
				}
				if netPrefix.Contains(ip) {
					if podSubnetLcuuid != "" {
						subnetLcuuid = podSubnetLcuuid
					} else {
						subnetLcuuid = common.GetUUID(k.podNetworkLcuuidCIDRs.networkLcuuid+podNetworkCIDR, uuid.Nil)
					}
					break
				}
			}
			if subnetLcuuid == "" {
				for key, v := range subnetLcuuidToCIDR {
					if v.Contains(ip) {
						subnetLcuuid = key
						break
					}
				}
			}
			if subnetLcuuid == "" {
				if (ip.Is4() && ipMask == 32) || (ip.Is6() && ipMask == 128) {
					switch {
					case ip.Is4():
						aggNoMaskV4Nets = append(aggNoMaskV4Nets, ipPrefix.String())
					case ip.Is6():
						aggNoMaskV6Nets = append(aggNoMaskV6Nets, ipPrefix.String())
					}
					ipToVinterfaceLcuuid[ipString] = vinterfaceLcuuid
				} else {
					rangePrefix, ok := ipPrefix.Range().Prefix()
					if !ok {
						log.Warningf("vinterface,ip pod ip (%s) to cidr format not valid", ipString)
					}
					subnetLcuuid = common.GetUUID(k.podNetworkLcuuidCIDRs.networkLcuuid+rangePrefix.String(), uuid.Nil)
					subnet := model.Subnet{
						Lcuuid:        subnetLcuuid,
						Name:          rangePrefix.String() + "_POD_NET",
						CIDR:          rangePrefix.String(),
						NetworkLcuuid: k.podNetworkLcuuidCIDRs.networkLcuuid,
						VPCLcuuid:     k.VPCUuid,
					}
					podSubnets = append(podSubnets, subnet)
					subnetLcuuidToCIDR[subnetLcuuid] = rangePrefix
				}
			}
			modelIP := model.IP{
				Lcuuid:           ipLcuuid,
				VInterfaceLcuuid: vinterfaceLcuuid,
				IP:               ip.String(),
				SubnetLcuuid:     subnetLcuuid,
				RegionLcuuid:     k.RegionUuid,
			}
			podIPsMap[ipLcuuid] = &modelIP
			delete(k.podIPToLcuuid, ip.String())
		}
	}

	// 聚合没有掩码的ip地址
	// 先获取已有的cidr
	existCIDR := []netaddr.IPPrefix{}
	for _, v := range subnetLcuuidToCIDR {
		existCIDR = append(existCIDR, v)
	}
	for _, c := range k.podNetworkLcuuidCIDRs.cidrs {
		cPrefix, err := netaddr.ParseIPPrefix(c)
		if err != nil {
			log.Errorf("vinterface,ip parse pod network cidr (%s) error: (%s)", c, err.Error())
			continue
		}
		existCIDR = append(existCIDR, cPrefix)
	}
	sort.Strings(aggNoMaskV4Nets)
	sort.Strings(aggNoMaskV6Nets)
	// v4,v6地址分开依次聚合，且聚合后的掩码不能超过设置的最大值
	for _, v4IPString := range aggNoMaskV4Nets {
		v4Prefix, _ := netaddr.ParseIPPrefix(v4IPString)
		v4ipNet := ipaddr.NewPrefix(v4Prefix.IPNet())
		aggFlag4 := false
		for i, v4CIDR := range noMaskPodV4CIDRs {
			intersecFlag4 := false
			if v4CIDR.Contains(v4ipNet) {
				aggFlag4 = true
				break
			}
			pSlisce := []ipaddr.Prefix{*v4ipNet, *v4CIDR}
			v4AggCIDR := ipaddr.Supernet(pSlisce)
			if v4AggCIDR == nil {
				continue
			}
			v4AggCIDRMask, _ := v4AggCIDR.IPNet.Mask.Size()
			if v4AggCIDRMask < k.PodNetIPv4CIDRMaxMask {
				continue
			}
			for _, cidr := range existCIDR {
				if !cidr.IP().Is4() {
					continue
				}
				eCIDR := ipaddr.NewPrefix(cidr.IPNet())
				// 如果聚合出来的cidr与已有的cidr有交集，则按规则重新聚合
				if v4AggCIDR.Overlaps(eCIDR) {
					intersecFlag4 = true
					break
				}
			}
			if !intersecFlag4 {
				noMaskPodV4CIDRs[i] = v4AggCIDR
				aggFlag4 = true
				break
			}
		}
		if !aggFlag4 {
			noMaskPodV4CIDRs = append(noMaskPodV4CIDRs, v4ipNet)
		}
	}

	// 同v4
	for _, v6IPString := range aggNoMaskV6Nets {
		v6Prefix, _ := netaddr.ParseIPPrefix(v6IPString)
		v6ipNet := ipaddr.NewPrefix(v6Prefix.IPNet())
		aggFlag6 := false
		for i, v6CIDR := range noMaskPodV6CIDRs {
			intersecFlag6 := false
			if v6CIDR.Contains(v6ipNet) {
				aggFlag6 = true
				break
			}
			pSlisce := []ipaddr.Prefix{*v6ipNet, *v6CIDR}
			v6AggCIDR := ipaddr.Supernet(pSlisce)
			if v6AggCIDR == nil {
				continue
			}
			v6AggCIDRMask, _ := v6AggCIDR.IPNet.Mask.Size()
			if v6AggCIDRMask < k.PodNetIPv6CIDRMaxMask {
				continue
			}
			for _, cidr := range existCIDR {
				if !cidr.IP().Is6() {
					continue
				}
				eCIDR := ipaddr.NewPrefix(cidr.IPNet())
				if v6CIDR.Overlaps(eCIDR) {
					intersecFlag6 = true
					break
				}
			}
			if !intersecFlag6 {
				noMaskPodV6CIDRs[i] = v6AggCIDR
				aggFlag6 = true
				break
			}
		}
		if !aggFlag6 {
			noMaskPodV6CIDRs = append(noMaskPodV6CIDRs, v6ipNet)
		}
	}
	// 添加聚合后的子网
	noMaskCIDRs := append(noMaskPodV4CIDRs, noMaskPodV6CIDRs...)
	aggNoMaskNets := append(aggNoMaskV4Nets, aggNoMaskV6Nets...)
	for _, ipPrefix := range noMaskCIDRs {
		subnetLcuuid := common.GetUUID(k.podNetworkLcuuidCIDRs.networkLcuuid+"NO_MASK"+ipPrefix.String(), uuid.Nil)
		subnet := model.Subnet{
			Lcuuid:        subnetLcuuid,
			Name:          ipPrefix.String() + "_POD_NET",
			CIDR:          ipPrefix.String(),
			NetworkLcuuid: k.podNetworkLcuuidCIDRs.networkLcuuid,
			VPCLcuuid:     k.VPCUuid,
		}
		podSubnets = append(podSubnets, subnet)
		ipNetPrefix, _ := netaddr.ParseIPPrefix(ipPrefix.String())
		subnetLcuuidToCIDR[subnetLcuuid] = ipNetPrefix
		// 将ip关联到聚合的子网
		for _, noMaskIPString := range aggNoMaskNets {
			noMaskIP, _ := netaddr.ParseIPPrefix(noMaskIPString)
			if !ipNetPrefix.Contains(noMaskIP.IP()) {
				log.Debugf("vinterface,ip ip (%s) not found aggregated subnet", noMaskIPString)
				continue
			}
			vinterfaceLcuuid := ipToVinterfaceLcuuid[noMaskIPString]
			noMaskIPPrefix, _ := netaddr.ParseIPPrefix(noMaskIPString)
			ipLcuuid := common.GetUUID(vinterfaceLcuuid+noMaskIPPrefix.IP().String(), uuid.Nil)
			podIPModel, ok := podIPsMap[ipLcuuid]
			if !ok {
				log.Debugf("vinterface,ip ip (%s) not relevancy subnet (%s)", noMaskIPPrefix.IP().String(), ipNetPrefix.String())
				continue
			}
			podIPModel.SubnetLcuuid = subnetLcuuid
		}
	}
	for _, v := range podIPsMap {
		podIPs = append(podIPs, *v)
	}

	// 生成pod的子网
	for i, pCIDR := range k.podNetworkLcuuidCIDRs.cidrs {
		if i > 1 {
			podSubnetLcuuid = common.GetUUID(k.podNetworkLcuuidCIDRs.networkLcuuid+pCIDR, uuid.Nil)
		}
		podSubnet := model.Subnet{
			Lcuuid:        podSubnetLcuuid,
			Name:          k.Name + "_POD_NET",
			CIDR:          pCIDR,
			NetworkLcuuid: k.podNetworkLcuuidCIDRs.networkLcuuid,
			VPCLcuuid:     k.VPCUuid,
		}
		podSubnets = append(podSubnets, podSubnet)
	}

	// 将genesis API没有获取到的POD IP mac置为全0
	for pIP, pLcuuid := range k.podIPToLcuuid {
		vinterfaceLcuuid := common.GetUUID(pLcuuid+common.VIF_DEFAULT_MAC, uuid.Nil)
		if !vinterfaceLcuuids.Contains(vinterfaceLcuuid) {
			vinterface := model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          common.VIF_TYPE_LAN,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceType:    common.VIF_DEVICE_TYPE_POD,
				DeviceLcuuid:  pLcuuid,
				NetworkLcuuid: k.podNetworkLcuuidCIDRs.networkLcuuid,
				VPCLcuuid:     k.VPCUuid,
				RegionLcuuid:  k.RegionUuid,
			}
			podVInterfaces = append(podVInterfaces, vinterface)
			vinterfaceLcuuids.Add(vinterfaceLcuuid)
		}
		modelIP := model.IP{
			Lcuuid:           common.GetUUID(vinterfaceLcuuid+pLcuuid, uuid.Nil),
			VInterfaceLcuuid: vinterfaceLcuuid,
			IP:               pIP,
			RegionLcuuid:     k.RegionUuid,
			SubnetLcuuid:     common.GetUUID(k.podNetworkLcuuidCIDRs.networkLcuuid, uuid.Nil),
		}
		podIPs = append(podIPs, modelIP)
	}
	// 处理nodeIP，生成port，ip，cidrs信息
	invalidNodeIPs := mapset.NewSet()
	nodeVinterfaceLcuuids := mapset.NewSet()
	for _, vItem := range vData {
		if vItem.KubernetesClusterID != k.ClusterID {
			continue
		}
		deviceType := vItem.DeviceType
		if deviceType != "docker-host" && deviceType != "kvm-host" {
			continue
		}
		hostIP := vItem.HostIP
		nMAC := vItem.Mac
		nName := vItem.Name

		nIPs, ok := hostIPToNodeIPs[hostIP]
		if !ok {
			log.Infof("vinterface,ip node (%s) not found", hostIP)
			continue
		}
		// 如果该host所对应的ip里面有能够获取到lcuuid的则说明这个ip是有效的node ip
		nodeIPSlice := []string{}
		for _, nodeIP := range nIPs {
			_, ok := k.nodeIPToLcuuid[nodeIP]
			if ok {
				nodeIPSlice = append(nodeIPSlice, nodeIP)
			}
		}
		if len(nodeIPSlice) == 0 {
			log.Infof("vinterface,ip (%s) node not found", nMAC)
			continue
		}

		nodeIP := nodeIPSlice[0]
		IPs := strings.Split(vItem.IPs, ",")
		for _, ipString := range IPs {
			ipPrefix, err := netaddr.ParseIPPrefix(ipString)
			if err != nil {
				log.Errorf("vinterface,ip parse cidrs (%s) error: (%s)", ipString, err.Error())
				continue
			}
			switch {
			// K8s API的容器节点IP，直接处理port和ip
			// 如果上报的node相关ip在node ip中，则使用上报ip的cidr替换掉聚合的node cidr
			case k8sNodeIPs.Contains(ipPrefix.IP().String()):
				// if is subdomain, don't record node ip and vinterface
				if k.isSubDomain {
					k8sNodeIPs.Remove(ipPrefix.IP().String())
					invalidNodeIPs.Add(ipPrefix.IP().String())
					log.Debugf("vinterface,ip the subdomain node ip (%s) already exists on the vm ip", ipPrefix.IP().String())
					continue
				}
				rangePrefix, ok := ipPrefix.Range().Prefix()
				if !ok {
					log.Warningf("vinterface,ip node ip (%s) to cidr format not valid", ipString)
				}
				if len(k.nodeNetworkLcuuidCIDRs.cidrs) == 1 {
					k.nodeNetworkLcuuidCIDRs.cidrs = []string{rangePrefix.String()}
				} else {
					nodeCIDRs := []string{}
					switch {
					case ipPrefix.IP().Is4():
						for _, c := range k.nodeNetworkLcuuidCIDRs.cidrs {
							nCIDR, err := netaddr.ParseIPPrefix(c)
							if err != nil {
								log.Warningf("vinterface,ip node cidr (%s) parse faild", c)
								continue
							}
							if nCIDR.IP().Is6() {
								nodeCIDRs = append(nodeCIDRs, c)
							}
						}
					case ipPrefix.IP().Is6():
						for _, c := range k.nodeNetworkLcuuidCIDRs.cidrs {
							nCIDR, err := netaddr.ParseIPPrefix(c)
							if err != nil {
								log.Warningf("vinterface,ip node cidr (%s) parse faild", c)
								continue
							}
							if nCIDR.IP().Is4() {
								nodeCIDRs = append(nodeCIDRs, c)
							}
						}
					}
					nodeCIDRs = append(nodeCIDRs, rangePrefix.String())
					k.nodeNetworkLcuuidCIDRs.cidrs = nodeCIDRs
				}
				vinterfaceLcuuid := common.GetUUID(k.UuidGenerate+nMAC, uuid.Nil)
				nodeLcuuid := k.nodeIPToLcuuid[ipPrefix.IP().String()]
				vinterface := model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Type:          common.VIF_TYPE_WAN,
					Mac:           nMAC,
					DeviceLcuuid:  nodeLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_POD_NODE,
					NetworkLcuuid: k.nodeNetworkLcuuidCIDRs.networkLcuuid,
					VPCLcuuid:     k.VPCUuid,
					RegionLcuuid:  k.RegionUuid,
				}
				nodeVInterfaces = append(nodeVInterfaces, vinterface)
				nodeVinterfaceLcuuids.Add(vinterfaceLcuuid)

				modelIP := model.IP{
					Lcuuid:           common.GetUUID(vinterfaceLcuuid+ipPrefix.IP().String(), uuid.Nil),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               ipPrefix.IP().String(),
					RegionLcuuid:     k.RegionUuid,
					SubnetLcuuid:     common.GetUUID(k.nodeNetworkLcuuidCIDRs.networkLcuuid, uuid.Nil),
				}
				nodeIPs = append(nodeIPs, modelIP)
				k8sNodeIPs.Remove(ipPrefix.IP().String())
			// 处理genesis额外上报的IP
			case k.PortNameRegex != "" && portNameRegex.MatchString(nName):
				if invalidNodeIPs.Contains(ipPrefix.IP().String()) {
					log.Debugf("vinterface,ip invalid node ip (%s)", ipPrefix.IP().String())
					continue
				}
				// 判断是否在节点默认cidr中，如果在则使用该cidr
				// 判断网段是否节点已有其他cidr中，如果在则使用该cidr
				// 判断网段是否在POD默认cidr中，如果在则使用该cidr
				// 判断网段是否在POD已有其他cidr中，如果在则使用该cidr
				// 否则基于该网段生成新的cidr
				nodeSubnetLcuuid := ""
				networkLcuuid := k.nodeNetworkLcuuidCIDRs.networkLcuuid
				hostip, err := netaddr.ParseIP(ipPrefix.IP().String())
				if err != nil {
					log.Errorf("vinterface,ip parse host ip (%s) error: (%s)", ipPrefix.IP().String(), err.Error())
					continue
				}

				for _, nCIDR := range k.nodeNetworkLcuuidCIDRs.cidrs {
					nodeIPPrefix, err := netaddr.ParseIPPrefix(nCIDR)
					if err != nil {
						log.Errorf("vinterface,ip parse node network cidr (%s) error: (%s)", nCIDR, err.Error())
						continue
					}
					if nodeIPPrefix.Contains(hostip) {
						nodeSubnetLcuuid = common.GetUUID(k.nodeNetworkLcuuidCIDRs.networkLcuuid, uuid.Nil)
					}
				}

				if nodeSubnetLcuuid == "" {
					for _, pCIDR := range k.podNetworkLcuuidCIDRs.cidrs {
						podIPPrefix, err := netaddr.ParseIPPrefix(pCIDR)
						if err != nil {
							log.Errorf("vinterface,ip parse pod network cidr (%s) error: (%s)", pCIDR, err.Error())
							continue
						}
						if podIPPrefix.Contains(hostip) {
							nodeSubnetLcuuid = common.GetUUID(k.podNetworkLcuuidCIDRs.networkLcuuid, uuid.Nil)
						}
					}
					if nodeSubnetLcuuid != "" {
						networkLcuuid = k.podNetworkLcuuidCIDRs.networkLcuuid
					}
				}

				if nodeSubnetLcuuid == "" {
					for key, value := range subnetLcuuidToCIDR {
						if value.Contains(hostip) {
							nodeSubnetLcuuid = key
						}
					}
					if nodeSubnetLcuuid != "" {
						networkLcuuid = k.podNetworkLcuuidCIDRs.networkLcuuid
					}
				}

				if nodeSubnetLcuuid == "" {
					hostIPMask, _ := ipPrefix.IPNet().Mask.Size()
					cidr, err := cloudcommon.IPAndMaskToCIDR(ipPrefix.IP().String(), hostIPMask)
					if err != nil {
						log.Errorf("vinterface,ip gnenerate host cidr (%s) error: (%s)", ipPrefix.IP().String(), err.Error())
						continue
					}
					nodeSubnetLcuuid = common.GetUUID(k.nodeNetworkLcuuidCIDRs.networkLcuuid+cidr, uuid.Nil)
					subnet := model.Subnet{
						Lcuuid:        nodeSubnetLcuuid,
						Name:          cidr + "_NODE_NET",
						CIDR:          cidr,
						NetworkLcuuid: networkLcuuid,
						VPCLcuuid:     k.VPCUuid,
					}
					nodeSubnets = append(nodeSubnets, subnet)
				}

				vinterfaceLcuuid := ""
				if nMAC == common.VIF_DEFAULT_MAC {
					vinterfaceLcuuid = common.GetUUID(k.UuidGenerate+nMAC+hostip.String(), uuid.Nil)
				} else {
					vinterfaceLcuuid = common.GetUUID(k.UuidGenerate+nMAC, uuid.Nil)
				}
				if !nodeVinterfaceLcuuids.Contains(vinterfaceLcuuid) {
					vinterface := model.VInterface{
						Lcuuid:        vinterfaceLcuuid,
						Type:          common.VIF_TYPE_LAN,
						Mac:           nMAC,
						DeviceLcuuid:  k.nodeIPToLcuuid[nodeIP],
						DeviceType:    common.VIF_DEVICE_TYPE_POD_NODE,
						NetworkLcuuid: networkLcuuid,
						VPCLcuuid:     k.VPCUuid,
						RegionLcuuid:  k.RegionUuid,
					}
					nodeVInterfaces = append(nodeVInterfaces, vinterface)
					nodeVinterfaceLcuuids.Add(vinterfaceLcuuid)
				}
				modelIP := model.IP{
					Lcuuid:           common.GetUUID(vinterfaceLcuuid+ipPrefix.IP().String(), uuid.Nil),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               ipPrefix.IP().String(),
					RegionLcuuid:     k.RegionUuid,
					SubnetLcuuid:     nodeSubnetLcuuid,
				}
				nodeIPs = append(nodeIPs, modelIP)
			}
		}
	}
	// 将genesis API没有获取到的容器节点IP mac置为全0
	for nodeIP, nodeLcuuid := range k.nodeIPToLcuuid {
		if !k8sNodeIPs.Contains(nodeIP) {
			continue
		}
		vinterfaceLcuuid := common.GetUUID(k.nodeNetworkLcuuidCIDRs.networkLcuuid+nodeLcuuid+common.VIF_DEFAULT_MAC, uuid.Nil)
		vinterface := model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          common.VIF_TYPE_WAN,
			Mac:           common.VIF_DEFAULT_MAC,
			DeviceLcuuid:  nodeLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_POD_NODE,
			NetworkLcuuid: k.nodeNetworkLcuuidCIDRs.networkLcuuid,
			VPCLcuuid:     k.VPCUuid,
			RegionLcuuid:  k.RegionUuid,
		}
		nodeVInterfaces = append(nodeVInterfaces, vinterface)
		modelIP := model.IP{
			Lcuuid:           common.GetUUID(vinterfaceLcuuid+nodeIP, uuid.Nil),
			VInterfaceLcuuid: vinterfaceLcuuid,
			IP:               nodeIP,
			RegionLcuuid:     k.RegionUuid,
			SubnetLcuuid:     common.GetUUID(k.nodeNetworkLcuuidCIDRs.networkLcuuid, uuid.Nil),
		}
		nodeIPs = append(nodeIPs, modelIP)
	}

	// 以获取到的node ip为依据，生成node子网
	nodeSubnetLcuuid := common.GetUUID(k.nodeNetworkLcuuidCIDRs.networkLcuuid, uuid.Nil)
	for i, nCIDR := range k.nodeNetworkLcuuidCIDRs.cidrs {
		if i > 1 {
			nodeSubnetLcuuid = common.GetUUID(k.nodeNetworkLcuuidCIDRs.networkLcuuid+nCIDR, uuid.Nil)
		}
		nodeSubnet := model.Subnet{
			Lcuuid:        nodeSubnetLcuuid,
			Name:          k.Name + "_NODE_NET",
			CIDR:          nCIDR,
			NetworkLcuuid: k.nodeNetworkLcuuidCIDRs.networkLcuuid,
			VPCLcuuid:     k.VPCUuid,
		}
		nodeSubnets = append(nodeSubnets, nodeSubnet)
	}

	log.Debug("get vinterfaces,ips complete")
	return
}
