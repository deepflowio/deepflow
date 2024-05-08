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

package genesis

import (
	"errors"

	"github.com/bitly/go-simplejson"
	mapset "github.com/deckarep/golang-set"
	"github.com/op/go-logging"
	"inet.af/netaddr"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/config"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/genesis"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/statsd"
)

var log = logging.MustGetLogger("cloud.genesis")

type Genesis struct {
	orgID           int
	ipV4CIDRMaxMask int
	ipV6CIDRMaxMask int
	defaultVpc      bool
	Name            string
	Lcuuid          string
	UuidGenerate    string
	regionUuid      string
	azLcuuid        string
	defaultVpcName  string
	ips             []cloudmodel.IP
	subnets         []cloudmodel.Subnet
	genesisData     genesis.GenesisSyncDataResponse
	cloudStatsd     statsd.CloudStatsd
}

func NewGenesis(orgID int, domain mysql.Domain, cfg config.CloudConfig) (*Genesis, error) {
	config, err := simplejson.NewJson([]byte(domain.Config))
	if err != nil {
		log.Error(err)
		return nil, err
	}
	ipV4MaxMask := config.Get("ipv4_cidr_max_mask").MustInt()
	if ipV4MaxMask == 0 {
		ipV4MaxMask = 16
	}
	ipV6MaxMask := config.Get("ipv6_cidr_max_mask").MustInt()
	if ipV6MaxMask == 0 {
		ipV6MaxMask = 64
	}
	return &Genesis{
		orgID:           orgID,
		ipV4CIDRMaxMask: ipV4MaxMask,
		ipV6CIDRMaxMask: ipV6MaxMask,
		Name:            domain.Name,
		Lcuuid:          domain.Lcuuid,
		UuidGenerate:    domain.DisplayName,
		defaultVpcName:  cfg.GenesisDefaultVpcName,
		regionUuid:      config.Get("region_uuid").MustString(),
		genesisData:     genesis.GenesisSyncDataResponse{},
		cloudStatsd:     statsd.NewCloudStatsd(),
	}, nil
}

func (g *Genesis) ClearDebugLog() {}

func (g *Genesis) CheckAuth() error {
	return nil
}

func (g *Genesis) GetStatter() statsd.StatsdStatter {
	globalTags := map[string]string{
		"domain_name": g.Name,
		"domain":      g.Lcuuid,
		"platform":    common.AGENT_SYNC_EN,
	}

	return statsd.StatsdStatter{
		GlobalTags: globalTags,
		Element:    statsd.GetCloudStatsd(g.cloudStatsd),
	}
}

func (g *Genesis) getGenesisData() (genesis.GenesisSyncDataResponse, error) {
	return genesis.GenesisService.GetGenesisSyncResponse(g.orgID)
}

func (g *Genesis) generateIPsAndSubnets() {
	g.ips = []cloudmodel.IP{}
	g.subnets = []cloudmodel.Subnet{}
	portIDToNetworkID := map[string]string{}
	portIDToVpcID := map[string]string{}
	NetworkIDToVpcID := map[string]string{}
	for _, port := range g.genesisData.Ports {
		portIDToNetworkID[port.Lcuuid] = port.NetworkLcuuid
		portIDToVpcID[port.Lcuuid] = port.VPCLcuuid
		NetworkIDToVpcID[port.NetworkLcuuid] = port.VPCLcuuid
	}
	// 这里需要根据trident上报的ip信息中last_seen字段进行去重
	// 当ip移到别的接口上时，内存中的ip信息可能会出现同一个ip在两个port上
	// 这时候会保留last_seen比较近的一个port的ip
	validIPs := []model.GenesisIP{}
	vpcIDToIPLastSeens := map[string][]model.GenesisIP{}
	for _, ip := range g.genesisData.IPLastSeens {
		vpcIDToIPLastSeens[portIDToVpcID[ip.Lcuuid]] = append(vpcIDToIPLastSeens[portIDToVpcID[ip.Lcuuid]], ip)
	}
	for _, ips := range vpcIDToIPLastSeens {
		ipToPorts := map[string][]model.GenesisIP{}
		for _, ip := range ips {
			ipToPorts[ip.IP] = append(ipToPorts[ip.IP], ip)
		}
		for _, ipLastSeens := range ipToPorts {
			ipFlag := ipLastSeens[0]
			timeFlag := ipFlag.LastSeen
			for _, ipLastSeen := range ipLastSeens[1:] {
				if ipLastSeen.LastSeen.After(timeFlag) {
					ipFlag = ipLastSeen
					timeFlag = ipLastSeen.LastSeen
				}
			}
			validIPs = append(validIPs, ipFlag)
		}
	}

	networkIDToIPLastSeens := map[string][]model.GenesisIP{}
	for _, ip := range validIPs {
		networkIDToIPLastSeens[portIDToNetworkID[ip.VinterfaceLcuuid]] = append(networkIDToIPLastSeens[portIDToNetworkID[ip.VinterfaceLcuuid]], ip)
	}

	// 由于目前没获取dhcp信息，所以在这里用一个子网内所有ip计算出一个最小网段
	for networkID, ipLastSeens := range networkIDToIPLastSeens {
		ipsWithMasklen := []model.GenesisIP{}
		ipsWithoutMasklen := []model.GenesisIP{}
		for _, ip := range ipLastSeens {
			if ip.Masklen != 0 {
				ipsWithMasklen = append(ipsWithMasklen, ip)
			} else {
				ipsWithoutMasklen = append(ipsWithoutMasklen, ip)
			}
		}
		knownCIDRs := mapset.NewSet()
		subnetMap := map[string]string{}
		for _, ip := range ipsWithMasklen {
			var cidr netaddr.IPPrefix
			ipNet, err := netaddr.ParseIP(ip.IP)
			if err != nil {
				log.Error(err.Error())
				continue
			}
			if ipNet.Is4() {
				cidr = netaddr.IPPrefixFrom(ipNet, uint8(ip.Masklen))
			} else if ipNet.Is6() {
				cidr = netaddr.IPPrefixFrom(ipNet, uint8(ip.Masklen))
			} else {
				continue
			}
			knownCIDRs.Add(cidr.Masked())
			if _, ok := subnetMap[cidr.Masked().String()]; !ok {
				subnet := cloudmodel.Subnet{
					Lcuuid:        common.GetUUIDByOrgID(g.orgID, networkID+cidr.Masked().String()),
					CIDR:          cidr.Masked().String(),
					NetworkLcuuid: networkID,
					VPCLcuuid:     NetworkIDToVpcID[networkID],
				}
				g.subnets = append(g.subnets, subnet)
				subnetMap[cidr.Masked().String()] = subnet.Lcuuid
			}
			modelIP := cloudmodel.IP{
				IP:               ip.IP,
				Lcuuid:           ip.Lcuuid,
				SubnetLcuuid:     subnetMap[cidr.Masked().String()],
				VInterfaceLcuuid: ip.VinterfaceLcuuid,
			}
			g.ips = append(g.ips, modelIP)
		}

		deducedCIDRs := []netaddr.IPPrefix{}
		prefixV4 := []netaddr.IPPrefix{}
		prefixV6 := []netaddr.IPPrefix{}
		for _, ip := range ipsWithoutMasklen {
			ipNet, err := netaddr.ParseIP(ip.IP)
			if err != nil {
				log.Warning(err.Error())
				continue
			}
			if ipNet.Is4() {
				prefixV4 = append(prefixV4, netaddr.IPPrefixFrom(ipNet, 32))
			} else if ipNet.Is6() {
				prefixV6 = append(prefixV6, netaddr.IPPrefixFrom(ipNet, 128))
			} else {
				log.Warningf("parse ip error: ip is (%s)", ipNet.String())
				continue
			}
		}
		aggreateV4CIDR := cloudcommon.GenerateCIDR(prefixV4, g.ipV4CIDRMaxMask)
		deducedCIDRs = append(deducedCIDRs, aggreateV4CIDR...)
		aggreateV6CIDR := cloudcommon.GenerateCIDR(prefixV6, g.ipV6CIDRMaxMask)
		deducedCIDRs = append(deducedCIDRs, aggreateV6CIDR...)
		for _, ip := range ipsWithoutMasklen {
			ipNet, err := netaddr.ParseIP(ip.IP)
			if err != nil {
				log.Warning(err.Error())
				continue
			}
			for _, cidr := range knownCIDRs.ToSlice() {
				if cidr.(netaddr.IPPrefix).Contains(ipNet) {
					modelIP := cloudmodel.IP{
						IP:               ip.IP,
						Lcuuid:           ip.Lcuuid,
						VInterfaceLcuuid: ip.VinterfaceLcuuid,
						SubnetLcuuid:     subnetMap[cidr.(netaddr.IPPrefix).String()],
					}
					g.ips = append(g.ips, modelIP)
				}
			}
			for _, cidr := range deducedCIDRs {
				if cidr.Contains(ipNet) {
					if _, ok := subnetMap[cidr.String()]; !ok {
						subnet := cloudmodel.Subnet{
							Lcuuid:        common.GetUUIDByOrgID(g.orgID, networkID+cidr.String()),
							NetworkLcuuid: networkID,
							CIDR:          cidr.String(),
							VPCLcuuid:     NetworkIDToVpcID[networkID],
						}
						g.subnets = append(g.subnets, subnet)
						subnetMap[cidr.String()] = subnet.Lcuuid
					}
					modelIP := cloudmodel.IP{
						Lcuuid:           ip.Lcuuid,
						IP:               ip.IP,
						VInterfaceLcuuid: ip.VinterfaceLcuuid,
						SubnetLcuuid:     subnetMap[cidr.String()],
					}
					g.ips = append(g.ips, modelIP)
				}
			}
		}
	}
}

func (g *Genesis) GetCloudData() (cloudmodel.Resource, error) {
	g.azLcuuid = ""
	g.defaultVpc = false
	g.cloudStatsd = statsd.NewCloudStatsd()

	if genesis.GenesisService == nil {
		return cloudmodel.Resource{}, errors.New("genesis service is nil")
	}

	genesisData, err := g.getGenesisData()
	if err != nil {
		return cloudmodel.Resource{}, err
	}
	g.genesisData = genesisData

	g.generateIPsAndSubnets()

	az, err := g.getAZ()
	if err != nil {
		return cloudmodel.Resource{}, err
	}

	vpcs, err := g.getVPCs()
	if err != nil {
		return cloudmodel.Resource{}, err
	}

	hosts, err := g.getHosts()
	if err != nil {
		return cloudmodel.Resource{}, err
	}

	networks, err := g.getNetworks()
	if err != nil {
		return cloudmodel.Resource{}, err
	}

	subnets, err := g.getSubnets()
	if err != nil {
		return cloudmodel.Resource{}, err
	}

	vms, err := g.getVMs()
	if err != nil {
		return cloudmodel.Resource{}, err
	}

	vinterfaces, err := g.getVinterfaces()
	if err != nil {
		return cloudmodel.Resource{}, err
	}

	ips, err := g.getIPs()
	if err != nil {
		return cloudmodel.Resource{}, err
	}
	if g.defaultVpc {
		vpc := cloudmodel.VPC{
			Lcuuid:       common.GetUUIDByOrgID(g.orgID, g.defaultVpcName),
			Name:         g.defaultVpcName,
			RegionLcuuid: g.regionUuid,
		}
		vpcs = append(vpcs, vpc)
	}

	resource := cloudmodel.Resource{
		IPs:         ips,
		VMs:         vms,
		VPCs:        vpcs,
		Hosts:       hosts,
		Subnets:     subnets,
		Networks:    networks,
		VInterfaces: vinterfaces,
		AZs:         []cloudmodel.AZ{az},
	}
	g.cloudStatsd.ResCount = statsd.GetResCount(resource)
	statsd.MetaStatsd.RegisterStatsdTable(g)
	return resource, nil
}
