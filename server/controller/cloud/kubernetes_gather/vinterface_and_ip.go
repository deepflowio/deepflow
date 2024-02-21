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

package kubernetes_gather

import (
	"errors"
	"regexp"
	"sort"
	"strings"

	"inet.af/netaddr"

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
	nodeSubnetLcuuidToCIDR := map[string]netaddr.IPPrefix{}
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
		log.Error(err.Error())
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
		if vItem.DeviceLcuuid != "" {
			deviceUUIDToPodLcuuid[vItem.DeviceLcuuid] = podLcuuid
		} else {
			vUUID := vItem.Lcuuid
			if vUUID == "" {
				continue
			}
			deviceUUIDToPodLcuuid[vUUID] = podLcuuid
		}
	}

	// 处理POD IP，生成port，ip，cidrs信息
	for _, vItem := range vData {
		if vItem.KubernetesClusterID != k.ClusterID {
			continue
		}
		if vItem.DeviceType != "docker-container" {
			continue
		}
		podLcuuid := deviceUUIDToPodLcuuid[vItem.DeviceLcuuid]
		if podLcuuid == "" {
			vUUID := vItem.Lcuuid
			podLcuuid = deviceUUIDToPodLcuuid[vUUID]
		}
		if podLcuuid == "" {
			log.Debugf("vinterface,ip port (%s) pod not found", vItem.Mac)
			continue
		}

		vMac := vItem.Mac
		if vItem.IFType == "ipvlan" {
			vMac = common.VIF_DEFAULT_MAC
		}

		vinterfaceLcuuid := common.GetUUID(podLcuuid+vItem.Mac, uuid.Nil)
		if !vinterfaceLcuuids.Contains(vinterfaceLcuuid) {
			vinterfaceLcuuids.Add(vinterfaceLcuuid)
			vinterface := model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          common.VIF_TYPE_LAN,
				Mac:           vMac,
				TapMac:        vItem.TapMac,
				NetnsID:       vItem.NetnsID,
				VTapID:        vItem.VtapID,
				DeviceType:    common.VIF_DEVICE_TYPE_POD,
				DeviceLcuuid:  podLcuuid,
				NetworkLcuuid: k.podNetworkLcuuidCIDRs.networkLcuuid,
				VPCLcuuid:     k.VPCUUID,
				RegionLcuuid:  k.RegionUUID,
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
					subnetLcuuid = common.GetUUID(k.podNetworkLcuuidCIDRs.networkLcuuid+podNetworkCIDR, uuid.Nil)
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
					if _, ok := subnetLcuuidToCIDR[subnetLcuuid]; !ok {
						podSubnets = append(podSubnets, model.Subnet{
							Lcuuid:        subnetLcuuid,
							Name:          rangePrefix.String() + "_POD_NET",
							CIDR:          rangePrefix.String(),
							NetworkLcuuid: k.podNetworkLcuuidCIDRs.networkLcuuid,
							VPCLcuuid:     k.VPCUUID,
						})
						subnetLcuuidToCIDR[subnetLcuuid] = rangePrefix
					}
				}
			}
			modelIP := model.IP{
				Lcuuid:           ipLcuuid,
				VInterfaceLcuuid: vinterfaceLcuuid,
				IP:               ip.String(),
				SubnetLcuuid:     subnetLcuuid,
				RegionLcuuid:     k.RegionUUID,
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
	for _, cidr := range k.podNetworkLcuuidCIDRs.cidrs {
		cPrefix, err := netaddr.ParseIPPrefix(cidr)
		if err != nil {
			log.Errorf("vinterface,ip parse pod network cidr (%s) error: (%s)", cidr, err.Error())
			continue
		}
		existCIDR = append(existCIDR, cPrefix)

		// 顺便生成已获取的 pod 子网
		pSubnetLcuuid := common.GetUUID(k.podNetworkLcuuidCIDRs.networkLcuuid+cidr, uuid.Nil)
		podSubnets = append(podSubnets, model.Subnet{
			Lcuuid:        pSubnetLcuuid,
			Name:          k.Name + "_POD_NET",
			CIDR:          cidr,
			NetworkLcuuid: k.podNetworkLcuuidCIDRs.networkLcuuid,
			VPCLcuuid:     k.VPCUUID,
		})
		subnetLcuuidToCIDR[pSubnetLcuuid] = cPrefix
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
		podSubnets = append(podSubnets, model.Subnet{
			Lcuuid:        subnetLcuuid,
			Name:          ipPrefix.String() + "_POD_NET",
			CIDR:          ipPrefix.String(),
			NetworkLcuuid: k.podNetworkLcuuidCIDRs.networkLcuuid,
			VPCLcuuid:     k.VPCUUID,
		})
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

	// 处理nodeIP，生成port，ip，cidrs信息
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
				rangePrefix, ok := ipPrefix.Range().Prefix()
				if !ok {
					log.Warningf("vinterface,ip node ip (%s) to cidr format not valid", ipString)
				}
				if len(k.nodeNetworkLcuuidCIDRs.cidrs) == 1 {
					k.nodeNetworkLcuuidCIDRs.cidrs = []string{rangePrefix.String()}
				} else {
					nodeCIDRs := map[string]string{}
					switch {
					case ipPrefix.IP().Is4():
						for _, c := range k.nodeNetworkLcuuidCIDRs.cidrs {
							nCIDR, err := netaddr.ParseIPPrefix(c)
							if err != nil {
								log.Warningf("vinterface,ip node cidr (%s) parse faild", c)
								continue
							}
							if nCIDR.IP().Is6() {
								nodeCIDRs[c] = ""
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
								nodeCIDRs[c] = ""
							}
						}
					}
					nodeCIDRs[rangePrefix.String()] = ""
					k.nodeNetworkLcuuidCIDRs.cidrs = cloudcommon.StringStringMapKeys(nodeCIDRs)
				}
				vinterfaceLcuuid := common.GetUUID(k.UuidGenerate+nMAC, uuid.Nil)
				nodeLcuuid := k.nodeIPToLcuuid[ipPrefix.IP().String()]
				vinterface := model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Type:          common.VIF_TYPE_WAN,
					Mac:           nMAC,
					NetnsID:       vItem.NetnsID,
					VTapID:        vItem.VtapID,
					DeviceLcuuid:  nodeLcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_POD_NODE,
					NetworkLcuuid: k.nodeNetworkLcuuidCIDRs.networkLcuuid,
					VPCLcuuid:     k.VPCUUID,
					RegionLcuuid:  k.RegionUUID,
				}
				nodeVInterfaces = append(nodeVInterfaces, vinterface)
				nodeVinterfaceLcuuids.Add(vinterfaceLcuuid)

				modelIP := model.IP{
					Lcuuid:           common.GetUUID(vinterfaceLcuuid+ipPrefix.IP().String(), uuid.Nil),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               ipPrefix.IP().String(),
					RegionLcuuid:     k.RegionUUID,
					SubnetLcuuid:     common.GetUUID(k.nodeNetworkLcuuidCIDRs.networkLcuuid+rangePrefix.String(), uuid.Nil),
				}
				nodeIPs = append(nodeIPs, modelIP)
				k8sNodeIPs.Remove(ipPrefix.IP().String())
			// 处理genesis额外上报的IP
			case k.PortNameRegex != "" && portNameRegex.MatchString(nName):
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
							nodeSubnetLcuuid = common.GetUUID(k.podNetworkLcuuidCIDRs.networkLcuuid+pCIDR, uuid.Nil)
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
					if _, ok := subnetLcuuidToCIDR[nodeSubnetLcuuid]; !ok {
						nodeSubnets = append(nodeSubnets, model.Subnet{
							Lcuuid:        nodeSubnetLcuuid,
							Name:          cidr + "_NODE_NET",
							CIDR:          cidr,
							NetworkLcuuid: networkLcuuid,
							VPCLcuuid:     k.VPCUUID,
						})
						subnetLcuuidToCIDR[nodeSubnetLcuuid] = ipPrefix
					}
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
						NetnsID:       vItem.NetnsID,
						VTapID:        vItem.VtapID,
						DeviceLcuuid:  k.nodeIPToLcuuid[nodeIP],
						DeviceType:    common.VIF_DEVICE_TYPE_POD_NODE,
						NetworkLcuuid: networkLcuuid,
						VPCLcuuid:     k.VPCUUID,
						RegionLcuuid:  k.RegionUUID,
					}
					nodeVInterfaces = append(nodeVInterfaces, vinterface)
					nodeVinterfaceLcuuids.Add(vinterfaceLcuuid)
				}
				modelIP := model.IP{
					Lcuuid:           common.GetUUID(vinterfaceLcuuid+ipPrefix.IP().String(), uuid.Nil),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               ipPrefix.IP().String(),
					RegionLcuuid:     k.RegionUUID,
					SubnetLcuuid:     nodeSubnetLcuuid,
				}
				nodeIPs = append(nodeIPs, modelIP)
			}
		}
	}

	// 以获取到的node ip为依据，生成node子网
	for _, nCIDR := range k.nodeNetworkLcuuidCIDRs.cidrs {
		nodeSubnetLcuuid := common.GetUUID(k.nodeNetworkLcuuidCIDRs.networkLcuuid+nCIDR, uuid.Nil)
		nodeSubnets = append(nodeSubnets, model.Subnet{
			Lcuuid:        nodeSubnetLcuuid,
			Name:          k.Name + "_NODE_NET",
			CIDR:          nCIDR,
			NetworkLcuuid: k.nodeNetworkLcuuidCIDRs.networkLcuuid,
			VPCLcuuid:     k.VPCUUID,
		})
		ipNetPrefix, _ := netaddr.ParseIPPrefix(nCIDR)
		subnetLcuuidToCIDR[nodeSubnetLcuuid] = ipNetPrefix
		nodeSubnetLcuuidToCIDR[nodeSubnetLcuuid] = ipNetPrefix
	}

	// 将genesis API没有获取到的容器节点IP mac置为全0
	for nodeIP, nodeLcuuid := range k.nodeIPToLcuuid {
		if !k8sNodeIPs.Contains(nodeIP) {
			continue
		}
		vinterfaceLcuuid := common.GetUUID(k.nodeNetworkLcuuidCIDRs.networkLcuuid+nodeLcuuid+common.VIF_DEFAULT_MAC, uuid.Nil)
		nodeVInterfaces = append(nodeVInterfaces, model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          common.VIF_TYPE_WAN,
			Mac:           common.VIF_DEFAULT_MAC,
			DeviceLcuuid:  nodeLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_POD_NODE,
			NetworkLcuuid: k.nodeNetworkLcuuidCIDRs.networkLcuuid,
			VPCLcuuid:     k.VPCUUID,
			RegionLcuuid:  k.RegionUUID,
		})
		var nodeSubnetLcuuid string
		nIPParse := netaddr.MustParseIP(nodeIP)
		for nLcuuid, cPrefix := range nodeSubnetLcuuidToCIDR {
			if cPrefix.Contains(nIPParse) {
				nodeSubnetLcuuid = nLcuuid
				break
			}
		}
		nodeIPs = append(nodeIPs, model.IP{
			Lcuuid:           common.GetUUID(vinterfaceLcuuid+nodeIP, uuid.Nil),
			VInterfaceLcuuid: vinterfaceLcuuid,
			IP:               nodeIP,
			RegionLcuuid:     k.RegionUUID,
			SubnetLcuuid:     nodeSubnetLcuuid,
		})
	}

	// 将genesis API没有获取到的POD IP mac置为全0
	// 首先将 ip 关联到已有的 pod subnet
	// 未关联到 subnet 的 ip 重新聚合为新的子网
	podLcuuidToPodIP := map[string]netaddr.IP{}
	podV4Cidrs := []netaddr.IPPrefix{}
	podV6Cidrs := []netaddr.IPPrefix{}
	for pIP, pLcuuid := range k.podIPToLcuuid {
		// 过滤掉 hostnetwork 类型的 pod ip
		if _, ok := k.nodeIPToLcuuid[pIP]; ok {
			continue
		}
		vinterfaceLcuuid := common.GetUUID(pLcuuid+common.VIF_DEFAULT_MAC, uuid.Nil)
		if !vinterfaceLcuuids.Contains(vinterfaceLcuuid) {
			vinterface := model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          common.VIF_TYPE_LAN,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceType:    common.VIF_DEVICE_TYPE_POD,
				DeviceLcuuid:  pLcuuid,
				NetworkLcuuid: k.podNetworkLcuuidCIDRs.networkLcuuid,
				VPCLcuuid:     k.VPCUUID,
				RegionLcuuid:  k.RegionUUID,
			}
			podVInterfaces = append(podVInterfaces, vinterface)
			vinterfaceLcuuids.Add(vinterfaceLcuuid)
		}

		var podSubnetLcuuid string
		pIPParse := netaddr.MustParseIP(pIP)
		for sLcuuid, cPrefix := range subnetLcuuidToCIDR {
			if cPrefix.Contains(pIPParse) {
				podSubnetLcuuid = sLcuuid
				break
			}
		}
		if podSubnetLcuuid == "" {
			switch {
			case pIPParse.Is4():
				pV4Cidr, err := pIPParse.Prefix(32)
				if err == nil {
					podV4Cidrs = append(podV4Cidrs, pV4Cidr)
				}
			case pIPParse.Is6():
				pV6Cidr, err := pIPParse.Prefix(128)
				if err == nil {
					podV6Cidrs = append(podV6Cidrs, pV6Cidr)
				}
			}
			podLcuuidToPodIP[pLcuuid] = pIPParse
			continue
		}
		modelIP := model.IP{
			Lcuuid:           common.GetUUID(vinterfaceLcuuid+pLcuuid, uuid.Nil),
			VInterfaceLcuuid: vinterfaceLcuuid,
			IP:               pIP,
			RegionLcuuid:     k.RegionUUID,
			SubnetLcuuid:     podSubnetLcuuid,
		}
		podIPs = append(podIPs, modelIP)
	}
	var pV4cidrs, pV6cidrs []string
	var pV4cidr, pV6cidr, pV4SLcuuid, pV6SLcuuid string
	if len(podV4Cidrs) != 0 {
		pV4cidrs = cloudcommon.AggregateCIDR(podV4Cidrs, 0)
		if len(pV4cidrs) == 1 {
			pV4cidr = pV4cidrs[0]
			pV4SLcuuid = common.GetUUID(k.podNetworkLcuuidCIDRs.networkLcuuid+pV4cidr, uuid.Nil)
			podSubnets = append(podSubnets, model.Subnet{
				Lcuuid:        pV4SLcuuid,
				Name:          k.Name + "_POD_NET",
				CIDR:          pV4cidr,
				NetworkLcuuid: k.podNetworkLcuuidCIDRs.networkLcuuid,
				VPCLcuuid:     k.VPCUUID,
			})
		}
	}
	if len(podV6Cidrs) != 0 {
		pV6cidrs = cloudcommon.AggregateCIDR(podV6Cidrs, 0)
		if len(pV6cidrs) == 1 {
			pV6cidr = pV6cidrs[0]
			pV6SLcuuid = common.GetUUID(k.podNetworkLcuuidCIDRs.networkLcuuid+pV6cidr, uuid.Nil)
			podSubnets = append(podSubnets, model.Subnet{
				Lcuuid:        pV6SLcuuid,
				Name:          k.Name + "_POD_NET",
				CIDR:          pV6cidr,
				NetworkLcuuid: k.podNetworkLcuuidCIDRs.networkLcuuid,
				VPCLcuuid:     k.VPCUUID,
			})
		}
	}
	for lcuuid, ip := range podLcuuidToPodIP {
		var sLcuuid string
		vinterfaceLcuuid := common.GetUUID(lcuuid+common.VIF_DEFAULT_MAC, uuid.Nil)
		switch {
		case ip.Is4():
			sLcuuid = pV4SLcuuid
		case ip.Is6():
			sLcuuid = pV6SLcuuid
		}
		if sLcuuid == "" {
			log.Infof("vinterface,ip pod ip (%s) not found subnet", ip.String())
			continue
		}
		modelIP := model.IP{
			Lcuuid:           common.GetUUID(vinterfaceLcuuid+lcuuid, uuid.Nil),
			VInterfaceLcuuid: vinterfaceLcuuid,
			IP:               ip.String(),
			RegionLcuuid:     k.RegionUUID,
			SubnetLcuuid:     sLcuuid,
		}
		podIPs = append(podIPs, modelIP)
	}

	log.Debug("get vinterfaces,ips complete")
	return
}
