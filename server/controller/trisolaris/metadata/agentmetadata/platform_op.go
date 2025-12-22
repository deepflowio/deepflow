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

package agentmetadata

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/proto"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/message/agent"
	. "github.com/deepflowio/deepflow/server/controller/common"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

type PlatformDataOP struct {
	// atomic.Value只能整体替换不能修改内部数据
	rawData              *atomic.Value // *PlatformRawData
	domainInterfaceProto *atomic.Value // *DomainInterfaceProto
	domainPeerConnProto  *atomic.Value // *DomainPeerConnProto
	domainCIDRProto      *atomic.Value // *DomainCIDRProto

	// ingester used platform data
	allPlatformDataForIngester *atomic.Value //*PlatformData

	// 生成的平台数据
	*DomainToPlatformData
	// db connect
	db *gorm.DB
	// 平台数据变化通知
	chDataChanged chan struct{}

	metaData *MetaData

	*Segment

	ORGID
}

func newPlatformDataOP(db *gorm.DB, metaData *MetaData) *PlatformDataOP {
	rawData := &atomic.Value{}
	rawData.Store(NewPlatformRawData(metaData.ORGID))

	domainInterfaceProto := &atomic.Value{}
	domainInterfaceProto.Store(NewDomainInterfaceProto(metaData.ORGID))

	domainPeerConnProto := &atomic.Value{}
	domainPeerConnProto.Store(NewDomainPeerConnProto())

	domainCIDRProto := &atomic.Value{}
	domainCIDRProto.Store(newDomainCIDRProto(0))

	allPlatformDataForIngester := &atomic.Value{}
	allPlatformDataForIngester.Store(NewPlatformData("", "", 0, INGESTER_ALL_PLATFORM_DATA))

	return &PlatformDataOP{
		rawData:                    rawData,
		domainInterfaceProto:       domainInterfaceProto,
		domainPeerConnProto:        domainPeerConnProto,
		domainCIDRProto:            domainCIDRProto,
		allPlatformDataForIngester: allPlatformDataForIngester,
		DomainToPlatformData:       newDomainToPlatformData(),
		db:                         db,
		chDataChanged:              make(chan struct{}, 1),
		Segment:                    newSegment(metaData.ORGID),
		metaData:                   metaData,
		ORGID:                      metaData.ORGID,
	}
}

// 有依赖 需要按顺序convert
func (p *PlatformDataOP) generateRawData() {
	dbDataCache := p.metaData.GetDBDataCache()
	r := NewPlatformRawData(p.metaData.ORGID)
	r.ConvertDBCache(dbDataCache)
	p.updateRawData(r)
}

func GetDefaultMaskLen(ip string) uint32 {
	if strings.Contains(ip, ":") {
		return 128
	}

	return 32
}

func generateProtoIpResource(ip string, maskLen uint32, subnetID uint32) *agent.IpResource {
	if maskLen == 0 {
		maskLen = GetDefaultMaskLen(ip)
	}
	var protoSubnetId *uint32
	if subnetID != 0 {
		protoSubnetId = &subnetID
	}
	return &agent.IpResource{
		Ip:       proto.String(ip),
		Masklen:  proto.Uint32(maskLen),
		SubnetId: protoSubnetId,
	}
}

type InterfaceProto struct {
	sInterface *agent.Interface
}

func (p *PlatformDataOP) generateVInterfaces() {
	dbDataCacheCache := p.metaData.GetDBDataCache()
	vifs := dbDataCacheCache.GetVInterfaces()
	if vifs == nil {
		return
	}
	length := len(vifs)
	sInterfaces := make([]*agent.Interface, 0, length)
	rawData := p.GetRawData()
	dipData := NewDomainInterfaceProto(p.metaData.ORGID)
	vifPubIps := []string{}
	platformVips := p.metaData.GetPlatformVips()
	for index, _ := range vifs {
		vif := vifs[index]
		typeIDKey := TypeIDKey{
			Type: vif.DeviceType,
			ID:   vif.DeviceID,
		}
		device, ok := rawData.typeIDToDevice[typeIDKey]
		if ok == false {
			log.Warningf(p.Logf("vif (lcuuid:%s, domain:%s) not found device(device_type:%d, device_id:%d)",
				vif.Lcuuid, vif.Domain, vif.DeviceType, vif.DeviceID))
			continue
		}
		var ipResourceData *IpResourceData
		ipResourceData, vifPubIps = rawData.generateIpResoureceData(vif, vifPubIps, platformVips)
		interfaceProto, err := rawData.vInterfaceToProto(vif, device, ipResourceData)
		if err != nil {
			log.Error(p.Log(err.Error()))
			continue
		}
		if p.metaData.config.GetNoIPOverlapping() {
			interfaceProto.sInterface.IfType = proto.Uint32(uint32(VIF_TYPE_WAN))
		}
		err = rawData.modifyInterfaceProto(vif, interfaceProto, device)
		if err != nil {
			log.Error(p.Log(err.Error()))
		}
		sInterfaces = append(sInterfaces, interfaceProto.sInterface)
		dipData.addInterfaceProto(vif, interfaceProto, rawData)
	}

	for _, fip := range rawData.floatingIPs {
		if !Find[string](vifPubIps, fip.IP) {
			maskLen := GetDefaultMaskLen(fip.IP)
			isVipInterface := rawData.checkIsVip(fip.IP, nil, platformVips)
			data := &agent.Interface{
				IfType:         proto.Uint32(uint32(VIF_TYPE_WAN)),
				EpcId:          proto.Uint32(uint32(fip.VPCID)),
				IpResources:    []*agent.IpResource{generateProtoIpResource(fip.IP, maskLen, 0)},
				IsVipInterface: proto.Bool(isVipInterface),
			}
			sInterfaces = append(sInterfaces, data)
			dipData.addFloatingIPProto(fip.Domain, data)
		}
	}

	ips := make([]*agent.IpResource, 0, len(rawData.noVInterfaceIDIPs))
	wanIsVipInterface := false
	for _, ip := range rawData.noVInterfaceIDIPs {
		wanIsVipInterface = rawData.checkIsVip(ip.IP, nil, platformVips)
		ipResource := generateProtoIpResource(ip.IP, 0, 0)
		ips = append(ips, ipResource)
		data := &agent.Interface{
			IfType:         proto.Uint32(uint32(VIF_TYPE_WAN)),
			IpResources:    []*agent.IpResource{ipResource},
			IsVipInterface: proto.Bool(wanIsVipInterface),
		}
		dipData.addNoVIfIDProto(ip.Domain, data)
	}

	if len(ips) > 0 {
		data := &agent.Interface{
			IfType:         proto.Uint32(uint32(VIF_TYPE_WAN)),
			IpResources:    ips,
			IsVipInterface: proto.Bool(wanIsVipInterface),
		}
		sInterfaces = append(sInterfaces, data)
		dipData.addWanIPsProto(data)
	}

	dipData.updateAllSimpleInterfaces(sInterfaces)
	p.updateDomainInterfaceProto(dipData)
}

func (p *PlatformDataOP) GetNoDomainPeerConns() TPeerConnections {
	return p.getDomainPeerConnProto().getNoDomainPeerConns()
}

func (p *PlatformDataOP) generatePeerConnections() {
	dbDataCache := p.metaData.GetDBDataCache()
	peerConns := dbDataCache.GetPeerConnections()

	rawData := p.GetRawData()
	dpcData := NewDomainPeerConnProto()
	for _, pc := range peerConns {
		localVPCID := pc.GetLocalVPCID()
		remoteVPCID := pc.GetRemoteVPCID()
		if pc.LocalDomain == pc.RemoteDomain && localVPCID != 0 && remoteVPCID != 0 {
			proto := &agent.PeerConnection{
				Id:          proto.Uint32(uint32(pc.ID)),
				LocalEpcId:  proto.Uint32(uint32(localVPCID)),
				RemoteEpcId: proto.Uint32(uint32(remoteVPCID)),
			}
			dpcData.addData(proto)
			dpcData.addDomainData(pc.LocalDomain, proto)
			continue
		}

		localVPCIDs := make([]int, 0)
		if localVPCID == 0 {
			localVPCIDs = rawData.domainUUIDToVPCIDs[pc.LocalDomain]
		} else {
			localVPCIDs = append(localVPCIDs, localVPCID)
		}
		remoteVPCIDs := make([]int, 0)
		if remoteVPCID == 0 {
			remoteVPCIDs = rawData.domainUUIDToVPCIDs[pc.RemoteDomain]
		} else {
			remoteVPCIDs = append(remoteVPCIDs, remoteVPCID)
		}
		for _, localVPCID := range localVPCIDs {
			for _, remoteVPCID := range remoteVPCIDs {
				if localVPCID == remoteVPCID {
					continue
				}
				proto := &agent.PeerConnection{
					Id:          proto.Uint32(uint32(pc.ID)),
					LocalEpcId:  proto.Uint32(uint32(localVPCID)),
					RemoteEpcId: proto.Uint32(uint32(remoteVPCID)),
				}
				dpcData.addData(proto)
				dpcData.addDomainData(pc.LocalDomain, proto)
				dpcData.addDomainData(pc.RemoteDomain, proto)
			}
		}
	}

	// Add CEN(Cloud Enterprise Network) data to peer connection.
	// Associate cen.vpc_ids in pairs in one direction.
	for _, cen := range dbDataCache.GetCENs() {
		for i := 0; i < len(cen.VPCIDs); i++ {
			for j := i + 1; j < len(cen.VPCIDs); j++ {
				data := &agent.PeerConnection{
					Id:          proto.Uint32(0),
					LocalEpcId:  proto.Uint32(uint32(cen.VPCIDs[i])),
					RemoteEpcId: proto.Uint32(uint32(cen.VPCIDs[j])),
				}
				dpcData.addData(data)
				dpcData.addDomainData(cen.Domain, data)
			}
		}
	}

	p.updateDomainPeerConnProto(dpcData)
}

func (p *PlatformDataOP) generateCIDRs() {
	rawData := p.GetRawData()
	dbDataCache := p.metaData.GetDBDataCache()
	uuidToRegion := rawData.uuidToRegion
	idToVPC := rawData.idToVPC
	networkIDToSubnets := rawData.networkIDToSubnets
	networks := dbDataCache.GetNetworks()
	dcProto := newDomainCIDRProto(len(networkIDToSubnets))
	for _, network := range networks {
		subnets, ok := networkIDToSubnets[network.ID]
		if ok == false {
			continue
		}
		for _, subnet := range subnets {
			netmask := netmask2masklen(subnet.Netmask)
			if judgeNet(subnet.Prefix, netmask) == false {
				continue
			}
			prefix := fmt.Sprintf("%s/%d", subnet.Prefix, netmask)
			regionID := uint32(0)
			if region, ok := uuidToRegion[network.Region]; ok {
				regionID = uint32(region.ID)
			}
			tunnelID := network.TunnelID
			if vpc, ok := idToVPC[network.VPCID]; ok {
				if vpc.TunnelID != 0 {
					tunnelID = vpc.TunnelID
				}
			}
			isVip := false
			if network.IsVIP != 0 {
				isVip = true
			}
			simplecidrType := agent.CidrType_LAN
			if p.metaData.config.GetNoIPOverlapping() || network.NetType == NETWORK_TYPE_WAN {
				simplecidrType = agent.CidrType_WAN
			}
			simplecidr := &agent.Cidr{
				Prefix:   proto.String(prefix),
				Type:     &simplecidrType,
				EpcId:    proto.Int32(int32(network.VPCID)),
				RegionId: proto.Uint32(uint32(regionID)),
				TunnelId: proto.Uint32(uint32(tunnelID)),
				IsVip:    proto.Bool(isVip),
			}
			dcProto.addSimpleCIDR(simplecidr)
			dcProto.addDomainSimpleCIDR(network.Domain, simplecidr)
			networkDomain := ""
			if network.SubDomain == "" || network.SubDomain == network.Domain {
				networkDomain = network.Domain
			} else {
				networkDomain = network.SubDomain
			}
			if networkDomain == "" {
				continue
			}
			dcProto.addSubOrDomainSimpleCIDR(networkDomain, simplecidr)
		}
	}

	vips := dbDataCache.GetVIPs()
	for _, vip := range vips {
		network, ok := rawData.vipIDToNetwork[vip.ID]
		if ok == false {
			continue
		}
		prefix := fmt.Sprintf("%s/%d", vip.IP, GetDefaultMaskLen(vip.IP))
		regionID := uint32(0)
		if region, ok := uuidToRegion[network.Region]; ok {
			regionID = uint32(region.ID)
		}
		tunnelID := network.TunnelID
		if vpc, ok := idToVPC[network.VPCID]; ok {
			if vpc.TunnelID != 0 {
				tunnelID = vpc.TunnelID
			}
		}
		simplecidrType := agent.CidrType_LAN
		if p.metaData.config.GetNoIPOverlapping() || network.NetType == NETWORK_TYPE_WAN {
			simplecidrType = agent.CidrType_WAN
		}
		simplecidr := &agent.Cidr{
			Prefix:   proto.String(prefix),
			Type:     &simplecidrType,
			EpcId:    proto.Int32(int32(network.VPCID)),
			RegionId: proto.Uint32(uint32(regionID)),
			TunnelId: proto.Uint32(uint32(tunnelID)),
			IsVip:    proto.Bool(true),
		}
		dcProto.addSimpleCIDR(simplecidr)
		dcProto.addDomainSimpleCIDR(vip.Domain, simplecidr)
	}
	p.updateDomainCIDRProto(dcProto)
}

func (p *PlatformDataOP) generateAllSimplePlatformData() {
	domainInterfaceProto := p.getDomainInterfaceProto()
	domainPeerConnProto := p.getDomainPeerConnProto()
	domainCIDRProto := p.getDomainCIDRProto()

	//生成所有简化数据
	aSPData := NewPlatformData("", "", 0, ALL_SIMPLE_PLATFORM_DATA)
	aSPData.setPlatformData(
		domainInterfaceProto.allSimpleInterfaces,
		domainPeerConnProto.peerConns,
		domainCIDRProto.simplecidrs)
	pASPData := p.GetAllSimplePlatformData()
	if pASPData == nil {
		aSPData.initVersion()
		p.updateAllsimpleplatformdata(aSPData)
	} else if !pASPData.equal(aSPData) {
		aSPData.setVersion(pASPData.GetVersion() + 1)
		p.updateAllsimpleplatformdata(aSPData)
	}
	log.Info(p.Logf("%s", p.allSimplePlatformData))

	// 生成简化数据，不包括pod
	aSPDExceptPod := NewPlatformData("", "", 0, ALL_SIMPLE_PLATFORM_DATA_EXCEPT_POD)
	aSPDExceptPod.setPlatformData(
		domainInterfaceProto.allSimpleInterfacesExceptPod,
		domainPeerConnProto.peerConns,
		domainCIDRProto.simplecidrs)
	pASPDExceptPod := p.GetAllSimplePlatformDataExceptPod()
	if pASPDExceptPod == nil {
		aSPDExceptPod.initVersion()
		p.updateAllSimplePlatformDataExceptPod(aSPDExceptPod)
	} else if !pASPDExceptPod.equal(aSPDExceptPod) {
		aSPDExceptPod.setVersion(pASPDExceptPod.GetVersion() + 1)
		p.updateAllSimplePlatformDataExceptPod(aSPDExceptPod)
	}

	log.Info(p.Logf("%s", p.allSimplePlatformDataExceptPod))
}

func (p *PlatformDataOP) generateDomainPlatformData() {
	domainInterfaceProto := p.getDomainInterfaceProto()
	domainPeerConnProto := p.getDomainPeerConnProto()
	domainCIDRProto := p.getDomainCIDRProto()

	dToAPData := make(DomainPlatformData)
	dToPDExceptPod := make(DomainPlatformData)
	dToPDOnlyPod := make(DomainPlatformData)

	dbDataCache := p.metaData.GetDBDataCache()
	domains := dbDataCache.GetDomains()
	// 生成云平台数据包含subdomain数据
	for _, domain := range domains {
		// 群内所有vinterface信息
		interfaces := domainInterfaceProto.domainToAllInterfaces[domain.Lcuuid]
		peerConnections := domainPeerConnProto.domainToPeerConns[domain.Lcuuid]
		cidrs := domainCIDRProto.domainToCIDRs[domain.Lcuuid]
		domainDate := NewPlatformData(domain.Name, domain.Lcuuid, 0, DOMAIN_TO_ALL_SIMPLE_PLATFORM_DATA)
		domainDate.setPlatformData(interfaces, peerConnections, cidrs)
		dToAPData[domain.Lcuuid] = domainDate

		// vinterface包含集群内非pod信息
		interfacesExceptPod := domainInterfaceProto.domainToInterfacesExceptPod[domain.Lcuuid]
		domainCIDRs := domainCIDRProto.domainOrSubdomainToCIDRs[domain.Lcuuid]
		domainDataExceptPod := NewPlatformData(domain.Name, domain.Lcuuid, 0, DOMAIN_TO_PLATFORM_DATA_EXCEPT_POD)
		domainDataExceptPod.setPlatformData(interfacesExceptPod, peerConnections, domainCIDRs)
		dToPDExceptPod[domain.Lcuuid] = domainDataExceptPod

		// domain仅包含pod信息
		interfacesOnlyPod := domainInterfaceProto.domainOrSubdomainToInterfacesOnlyPod[domain.Lcuuid]
		domainDataOnlyPod := NewPlatformData(domain.Name, domain.Lcuuid, 0, DOMAIN_TO_PLATFORM_DATA_ONLY_POD)
		domainDataOnlyPod.setPlatformData(interfacesOnlyPod, peerConnections, domainCIDRs)
		dToPDOnlyPod[domain.Lcuuid] = domainDataOnlyPod
	}

	// subdomain 只有pod信息
	subDomains := dbDataCache.GetSubDomains()
	for _, subDomain := range subDomains {
		interfaces := domainInterfaceProto.domainOrSubdomainToInterfacesOnlyPod[subDomain.Lcuuid]
		peerConnections := domainPeerConnProto.domainToPeerConns[subDomain.Lcuuid]
		cidrs := domainCIDRProto.domainOrSubdomainToCIDRs[subDomain.Lcuuid]
		domainDataOnlyPod := NewPlatformData(subDomain.Name, subDomain.Lcuuid, 0, DOMAIN_TO_PLATFORM_DATA_ONLY_POD)
		domainDataOnlyPod.setPlatformData(interfaces, peerConnections, cidrs)
		dToPDOnlyPod[subDomain.Lcuuid] = domainDataOnlyPod
	}

	noDomainData := NewPlatformData("no domain", "", 0, NO_DOMAIN_TO_PLATFORM)
	noDomainData.setPlatformData(nil, domainPeerConnProto.getNoDomainPeerConns(), nil)
	oldNoDOmainDat := p.GetNoDomainPlatformData()
	if oldNoDOmainDat == nil {
		noDomainData.initVersion()
		p.updateNoDomainPlatformData(noDomainData)
	} else if !noDomainData.equal(oldNoDOmainDat) {
		noDomainData.setVersion(oldNoDOmainDat.GetVersion() + 1)
		p.updateNoDomainPlatformData(noDomainData)
	}

	if !p.GetDomainToAllPlatformData().checkVersion(dToAPData, int(p.ORGID)) {
		p.updateDomainToAllPlatformData(dToAPData)
	}
	if !p.GetDomainToPlatformDataExceptPod().checkVersion(dToPDExceptPod, int(p.ORGID)) {
		p.updateDomainToPlatformDataExceptPod(dToPDExceptPod)
	}
	if !p.GetDomainToPlatformDataOnlyPod().checkVersion(dToPDOnlyPod, int(p.ORGID)) {
		p.updateDomainToPlatformDataOnlyPod(dToPDOnlyPod)
	}
}

func (p *PlatformDataOP) GetRawData() *PlatformRawData {
	return p.rawData.Load().(*PlatformRawData)
}

func (p *PlatformDataOP) updateRawData(r *PlatformRawData) {
	p.rawData.Store(r)
}

func (p *PlatformDataOP) getDomainInterfaceProto() *DomainInterfaceProto {
	return p.domainInterfaceProto.Load().(*DomainInterfaceProto)
}

func (p *PlatformDataOP) updateDomainInterfaceProto(i *DomainInterfaceProto) {
	p.domainInterfaceProto.Store(i)
}

func (p *PlatformDataOP) getDomainPeerConnProto() *DomainPeerConnProto {
	return p.domainPeerConnProto.Load().(*DomainPeerConnProto)
}

func (p *PlatformDataOP) updateDomainPeerConnProto(c *DomainPeerConnProto) {
	p.domainPeerConnProto.Store(c)
}

func (p *PlatformDataOP) getDomainCIDRProto() *DomainCIDRProto {
	return p.domainCIDRProto.Load().(*DomainCIDRProto)
}

func (p *PlatformDataOP) updateDomainCIDRProto(c *DomainCIDRProto) {
	p.domainCIDRProto.Store(c)
}

func (p *PlatformDataOP) GetAllPlatformDataForIngester() *PlatformData {
	return p.allPlatformDataForIngester.Load().(*PlatformData)
}

func (p *PlatformDataOP) updateAllPlatformDataForIngester(d *PlatformData) {
	p.allPlatformDataForIngester.Store(d)
}

func (p *PlatformDataOP) GetSegment() *Segment {
	return p.Segment
}

// 保证所有遍历都是有序的
func (p *PlatformDataOP) generateBasePlatformData() {
	start := time.Now()
	p.generateVInterfaces()
	p.generatePeerConnections()
	p.generateCIDRs()
	p.generateAllSimplePlatformData()
	p.generateDomainPlatformData()
	elapsed := time.Since(start)
	log.Info(p.Logf("generate platform data cost: %s", elapsed))
}

func (p *PlatformDataOP) initData() {
	p.generateRawData()
	p.generateBasePlatformData()
	p.generateBaseSegments(p.GetRawData())
}

func (p *PlatformDataOP) GetPlatformDataChangedCh() <-chan struct{} {
	return p.chDataChanged
}

func (p *PlatformDataOP) putPlatformDataChange() {
	select {
	case p.chDataChanged <- struct{}{}:
	default:
		break
	}
}

func (p *PlatformDataOP) GeneratePlatformData() {
	oldRawData := p.GetRawData()
	p.generateRawData()
	newRawData := p.GetRawData()
	if !newRawData.equal(oldRawData) {
		p.generateBasePlatformData()
		p.generateBaseSegments(newRawData)
		p.putPlatformDataChange()
	}
}
