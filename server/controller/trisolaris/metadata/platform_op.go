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

package metadata

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/proto"
	"gorm.io/gorm"

	"github.com/deepflowys/deepflow/message/trident"
	. "github.com/deepflowys/deepflow/server/controller/common"
	models "github.com/deepflowys/deepflow/server/controller/db/mysql"
	. "github.com/deepflowys/deepflow/server/controller/trisolaris/common"
	. "github.com/deepflowys/deepflow/server/controller/trisolaris/utils"
)

type PlatformDataOP struct {
	// atomic.Value只能整体替换不能修改内部数据
	rawData              *atomic.Value // *PlatformRawData
	domainInterfaceProto *atomic.Value // *DomainInterfaceProto
	domainPeerConnProto  *atomic.Value // *DomainPeerConnProto
	domainCIDRProto      *atomic.Value // *DomainCIDRProto
	// droplet使用的数据
	dropletPlatformData *atomic.Value //*PlatformData

	// 生成的平台数据
	*DomainToPlatformData
	// db connect
	db *gorm.DB
	// 平台数据变化通知
	chDataChanged chan struct{}

	metaData *MetaData

	*Segment

	podIPs *atomic.Value // []*trident.PodIp
}

func newPlatformDataOP(db *gorm.DB, metaData *MetaData) *PlatformDataOP {
	rawData := &atomic.Value{}
	rawData.Store(NewPlatformRawData())

	domainInterfaceProto := &atomic.Value{}
	domainInterfaceProto.Store(NewDomainInterfaceProto())

	domainPeerConnProto := &atomic.Value{}
	domainPeerConnProto.Store(NewDomainPeerConnProto(0))

	domainCIDRProto := &atomic.Value{}
	domainCIDRProto.Store(newDomainCIDRProto(0))

	dropletPlatformData := &atomic.Value{}
	dropletPlatformData.Store(NewPlatformData("", "", 0, DROPLET_PLATFORM_DATA))

	return &PlatformDataOP{
		rawData:              rawData,
		domainInterfaceProto: domainInterfaceProto,
		domainPeerConnProto:  domainPeerConnProto,
		domainCIDRProto:      domainCIDRProto,
		dropletPlatformData:  dropletPlatformData,
		DomainToPlatformData: newDomainToPlatformData(),
		db:                   db,
		chDataChanged:        make(chan struct{}, 1),
		Segment:              newSegment(),
		metaData:             metaData,
		podIPs:               &atomic.Value{},
	}
}

// 有依赖 需要按顺序convert
func (p *PlatformDataOP) generateRawData() {
	dbDataCache := p.metaData.GetDBDataCache()
	r := NewPlatformRawData()
	r.ConvertDBCache(dbDataCache)
	p.updateRawData(r)
}

func GetDefaultMaskLen(ip string) uint32 {
	if strings.Contains(ip, ":") {
		return 128
	}

	return 32
}

func generateProtoIpResource(ip string, maskLen uint32, subnetID uint32) *trident.IpResource {
	if maskLen == 0 {
		maskLen = GetDefaultMaskLen(ip)
	}
	var protoSubnetId *uint32
	if subnetID != 0 {
		protoSubnetId = &subnetID
	}
	return &trident.IpResource{
		Ip:       proto.String(ip),
		Masklen:  proto.Uint32(maskLen),
		SubnetId: protoSubnetId,
	}
}

type InterfaceProto struct {
	aInterface *trident.Interface
	sInterface *trident.Interface
}

func (p *PlatformDataOP) generateVInterfaces() {
	dbDataCacheCache := p.metaData.GetDBDataCache()
	vifs := dbDataCacheCache.GetVInterfaces()
	if vifs == nil {
		return
	}
	length := len(vifs)
	sInterfaces := make([]*trident.Interface, 0, length)
	aInterfaces := make([]*trident.Interface, 0, length)
	rawData := p.GetRawData()
	dipData := NewDomainInterfaceProto()
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
			log.Warningf("vif (luccid:%s, domain:%s) not found device(device_type:%d, device_id:%d)",
				vif.Lcuuid, vif.Domain, vif.DeviceType, vif.DeviceID)
			continue
		}
		var ipResourceData *IpResourceData
		ipResourceData, vifPubIps = rawData.generateIpResoureceData(vif, vifPubIps, platformVips)
		interfaceProto, err := rawData.vInterfaceToProto(vif, device, ipResourceData)
		if err != nil {
			log.Error(err)
			continue
		}
		err = rawData.modifyInterfaceProto(vif, interfaceProto, device)
		if err != nil {
			log.Error(err)
		}
		sInterfaces = append(sInterfaces, interfaceProto.sInterface)
		aInterfaces = append(aInterfaces, interfaceProto.aInterface)
		dipData.addInterfaceProto(vif, interfaceProto)
	}

	for _, fip := range rawData.floatingIPs {
		if !Find[string](vifPubIps, fip.IP) {
			maskLen := GetDefaultMaskLen(fip.IP)
			isVipInterface := rawData.checkIsVip(fip.IP, nil, platformVips)
			data := &trident.Interface{
				IfType:         proto.Uint32(uint32(VIF_TYPE_WAN)),
				EpcId:          proto.Uint32(uint32(fip.VPCID)),
				IpResources:    []*trident.IpResource{generateProtoIpResource(fip.IP, maskLen, 0)},
				IsVipInterface: proto.Bool(isVipInterface),
			}
			aInterfaces = append(aInterfaces, data)
			sInterfaces = append(sInterfaces, data)
			dipData.addFloatingIPProto(fip.Domain, data)
		}
	}

	ips := make([]*trident.IpResource, 0, len(rawData.noVInterfaceIDIPs))
	wanIsVipInterface := false
	for _, ip := range rawData.noVInterfaceIDIPs {
		wanIsVipInterface = rawData.checkIsVip(ip.IP, nil, platformVips)
		ipResource := generateProtoIpResource(ip.IP, 0, 0)
		ips = append(ips, ipResource)
		data := &trident.Interface{
			IfType:         proto.Uint32(uint32(VIF_TYPE_WAN)),
			IpResources:    []*trident.IpResource{ipResource},
			IsVipInterface: proto.Bool(wanIsVipInterface),
		}
		dipData.addNoVIfIDProto(ip.Domain, data)
	}

	if len(ips) > 0 {
		data := &trident.Interface{
			IfType:         proto.Uint32(uint32(VIF_TYPE_WAN)),
			IpResources:    ips,
			IsVipInterface: proto.Bool(wanIsVipInterface),
		}
		aInterfaces = append(aInterfaces, data)
		sInterfaces = append(sInterfaces, data)
		dipData.allSimpleInterfacesExceptPod = append(
			dipData.allSimpleInterfacesExceptPod, data)
	}

	dipData.allSimpleInterfaces = sInterfaces
	dipData.allCompleteInterfaces = aInterfaces
	p.updateDomainInterfaceProto(dipData)
}

func (p *PlatformDataOP) generatePeerConnections() {
	dbDataCache := p.metaData.GetDBDataCache()
	peerConns := dbDataCache.GetPeerConnections()
	dpcData := NewDomainPeerConnProto(len(peerConns))
	for _, pc := range peerConns {
		data := &trident.PeerConnection{
			Id:          proto.Uint32(uint32(pc.ID)),
			LocalEpcId:  proto.Uint32(uint32(pc.LocalVPCID)),
			RemoteEpcId: proto.Uint32(uint32(pc.RemoteVPCID)),
		}
		dpcData.addData(pc.Domain, data)
	}

	p.updateDomainPeerConnProto(dpcData)
}

func (p *PlatformDataOP) generateCIDRs() {
	rawData := p.GetRawData()
	dbDataCache := p.metaData.GetDBDataCache()
	uuidToRegion := rawData.uuidToRegion
	uuidToAZ := rawData.uuidToAZ
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
			azID := uint32(0)
			if az, ok := uuidToAZ[network.AZ]; ok {
				azID = uint32(az.ID)
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
			cidrType := trident.CidrType_LAN
			if network.NetType == NETWORK_TYPE_WAN {
				cidrType = trident.CidrType_WAN
			}
			cidr := &trident.Cidr{
				Prefix:   proto.String(prefix),
				Type:     &cidrType,
				EpcId:    proto.Int32(int32(network.VPCID)),
				SubnetId: proto.Uint32(uint32(network.ID)),
				RegionId: proto.Uint32(uint32(regionID)),
				AzId:     proto.Uint32(uint32(azID)),
				TunnelId: proto.Uint32(uint32(tunnelID)),
				IsVip:    proto.Bool(isVip),
			}
			simplecidr := &trident.Cidr{
				Prefix:   proto.String(prefix),
				Type:     &cidrType,
				EpcId:    proto.Int32(int32(network.VPCID)),
				RegionId: proto.Uint32(uint32(regionID)),
				TunnelId: proto.Uint32(uint32(tunnelID)),
				IsVip:    proto.Bool(isVip),
			}
			dcProto.addCIDR(cidr)
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
	p.updateDomainCIDRProto(dcProto)
}

func (p *PlatformDataOP) generateDropletPlatformData() {
	domainInterfaceProto := p.getDomainInterfaceProto()
	domainPeerConnProto := p.getDomainPeerConnProto()
	domainCIDRProto := p.getDomainCIDRProto()

	// 生成droplet数据
	newDropletPlatformData := NewPlatformData("", "", 0, DROPLET_PLATFORM_DATA)
	newDropletPlatformData.setPlatformData(domainInterfaceProto.allCompleteInterfaces,
		domainPeerConnProto.peerConns, domainCIDRProto.cidrs)
	oldDropletPlatformData := p.getDropletPlatformData()
	if oldDropletPlatformData.GetVersion() == 0 {
		newDropletPlatformData.setVersion(uint64(time.Now().Unix()))
		p.updateDropletPlatformData(newDropletPlatformData)
	} else if !newDropletPlatformData.equal(oldDropletPlatformData) {
		newDropletPlatformData.setVersion(oldDropletPlatformData.GetVersion() + 1)
		p.updateDropletPlatformData(newDropletPlatformData)
	}

	log.Info(p.getDropletPlatformData())
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
	log.Info(p.allSimplePlatformData)

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

	log.Info(p.allSimplePlatformDataExceptPod)
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
		dToPDOnlyPod[subDomain.Name] = domainDataOnlyPod
	}

	if !p.GetDomainToAllPlatformData().checkVersion(dToAPData) {
		p.updateDomainToAllPlatformData(dToAPData)
	}
	if !p.GetDomainToPlatformDataExceptPod().checkVersion(dToPDExceptPod) {
		p.updateDomainToPlatformDataExceptPod(dToPDExceptPod)
	}
	if !p.GetDomainToPlatformDataOnlyPod().checkVersion(dToPDOnlyPod) {
		p.updateDomainToPlatformDataOnlyPod(dToPDOnlyPod)
	}
}

func (p *PlatformDataOP) GetPodIPs() []*trident.PodIp {
	reuslt, ok := p.podIPs.Load().([]*trident.PodIp)
	if ok {
		return reuslt
	}
	return nil
}

func (p *PlatformDataOP) updatePodIPs(podIPs []*trident.PodIp) {
	p.podIPs.Store(podIPs)
}

func (p *PlatformDataOP) generatePodIPS() {
	rawData := p.GetRawData()
	pods := p.metaData.GetDBDataCache().GetPods()
	podIPs := make([]*trident.PodIp, 0, len(pods))
	for _, pod := range pods {
		vifs, ok := rawData.podIDToVifs[pod.ID]
		if ok == false {
			continue
		}
		for vif := range vifs.Iter() {
			podVif := vif.(*models.VInterface)
			ips, ok := rawData.vInterfaceIDToIP[podVif.ID]
			if ok == false || len(ips) == 0 {
				continue
			}
			data := &trident.PodIp{
				PodId:        proto.Uint32(uint32(pod.ID)),
				PodName:      proto.String(pod.Name),
				EpcId:        proto.Uint32(uint32(pod.VPCID)),
				Ip:           proto.String(ips[0].GetIp()),
				PodClusterId: proto.Uint32(uint32(pod.PodClusterID)),
			}
			podIPs = append(podIPs, data)
			break
		}
	}
	p.updatePodIPs(podIPs)
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

func (p *PlatformDataOP) getDropletPlatformData() *PlatformData {
	return p.dropletPlatformData.Load().(*PlatformData)
}

func (p *PlatformDataOP) updateDropletPlatformData(d *PlatformData) {
	p.dropletPlatformData.Store(d)
}

func (p *PlatformDataOP) GetDropletPlatforDataVersion() uint64 {
	return p.getDropletPlatformData().GetPlatformDataVersion()
}

func (p *PlatformDataOP) GetDropletPlatforDataStr() []byte {
	return p.getDropletPlatformData().GetPlatformDataStr()
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
	p.generateDropletPlatformData()
	p.generateAllSimplePlatformData()
	p.generateDomainPlatformData()
	p.generatePodIPS()
	elapsed := time.Since(start)
	log.Info("generate platform data cost:", elapsed)
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
