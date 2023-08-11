/**
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

package mysql

import (
	"fmt"
	"net"

	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

const (
	VL2_TYPE_NET_WAN = 3
)

type Network struct {
	DataProvider
	dataTool *NetworkToolData
}

func NewNetwork() *Network {
	dp := &Network{newDataProvider(ctrlcommon.RESOURCE_TYPE_NETWORK_EN), new(NetworkToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *Network) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.networks {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *Network) generateOne(item mysql.Network) common.ResponseElem {
	d := MySQLModelToMap(item)
	if _, ok := d["VPC_ID"]; ok {
		d["EPC_ID"] = item.VPCID
		delete(d, "VPC_ID")
	}

	d["AZ_NAME"] = p.dataTool.azLcuuidToName[item.AZ]
	d["REGION_NAME"] = p.dataTool.regionLcuuidToName[item.Region]
	d["DOMAIN_NAME"] = p.dataTool.domainLcuuidToName[item.Domain]
	d["EPC_NAME"] = p.dataTool.vpcIDToName[item.VPCID]
	d["VM_COUNT"] = len(p.dataTool.vl2IDToVMIDs[item.ID])
	// TODO(weiqiang): delete
	if item.ID == 4126 {
		log.Infof("weiqinag vl2IDToVMIDs: %#v", p.dataTool.vl2IDToVMIDs[item.ID])
	}
	d["POD_COUNT"] = len(p.dataTool.vl2IDToPodIDs[item.ID])

	var routers []interface{}
	for vgwID := range p.dataTool.vl2IDToVGWIDs[item.ID] {
		_, ok := p.dataTool.vgwIDToVGW[vgwID]
		if !ok {
			continue
		}
		routers = append(routers, map[string]interface{}{
			"ID": vgwID,
		})
	}
	d["ROUTERS"] = routers
	d["ROUTER_COUNT"] = len(p.dataTool.vl2IDToVGWIDs[item.ID])

	var nets []interface{}
	for _, netID := range p.dataTool.vl2IDToNetIDs[item.ID] {
		subnet, ok := p.dataTool.idToSubnet[netID]
		if !ok {
			continue
		}

		if item.NetType == VL2_TYPE_NET_WAN &&
			subnet.Prefix == "0.0.0.0" &&
			subnet.Netmask == "0.0.0.0" {
			continue
		}
		s := MySQLModelToMap(subnet)
		s["DOMAIN"] = item.Domain
		maskLen, err := netmask2masklen(subnet.Netmask)
		if err != nil {
			log.Error(err)
		} else {
			s["NETMASK"] = maskLen
		}
		nets = append(nets, s)
	}
	d["NETS"] = nets

	var ipCount int
	for vifID := range p.dataTool.vl2IDToVIFIDs[item.ID] {
		vif, ok := p.dataTool.vifIDToVIF[vifID]
		if !ok {
			continue
		}
		ipCount += len(p.dataTool.vifIDToWANIPs[vifID]) + len(p.dataTool.vifIDToLANIPs[vif.ID])
		// TODO(weiqiang): delete
		if item.ID == 4096 {
			log.Infof("weiqinag ipCount: %v, %v, %v", ipCount, len(p.dataTool.vifIDToWANIPs[vifID]), len(p.dataTool.vifIDToLANIPs[vif.ID]))
		}
	}
	d["IP_COUNT"] = ipCount
	// TODO(weiqiang): delete
	if item.ID == 4126 {
		log.Infof("weiqinag ipCount: %v", ipCount)
	}

	// TODO(weiqiang):
	// VM_COUNT
	// IP_COUNT

	return d
}

func netmask2masklen(netmask string) (int, error) {
	ip := net.ParseIP(netmask)
	if ip == nil {
		return 0, fmt.Errorf("Invalid netmask: %s", netmask)
	}

	mask := ip.DefaultMask()
	ones, _ := mask.Size()
	return ones, nil
}

type NetworkToolData struct {
	networks []mysql.Network

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
	vpcIDToName        map[int]string
	azLcuuidToName     map[string]string

	vl2IDToVMIDs map[int][]int
	vmIDToVIFIDs map[int][]int
	vifIDToVIF   map[int]mysql.VInterface
	vmIDToFIPIDs map[int][]int
	fipIDToFIP   map[int]mysql.FloatingIP

	vl2IDToPodIDs map[int][]int
	podIDToVIFIDs map[int][]int

	vl2IDToVGWIDs map[int][]int
	vgwIDToVGW    map[int]mysql.VRouter
	vgwIDToVIFIDs map[int][]int
	vl2IDToNetIDs map[int][]int
	idToSubnet    map[int]mysql.Subnet

	vl2IDToVIFIDs map[int][]int
	vifIDToWANIPs map[int]map[string]struct{}
	vifIDToLANIPs map[int]map[string]struct{}
}

func (td *NetworkToolData) Init() *NetworkToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)
	td.azLcuuidToName = make(map[string]string)

	td.vl2IDToVMIDs = make(map[int][]int)
	td.vmIDToVIFIDs = make(map[int][]int)
	td.vifIDToVIF = make(map[int]mysql.VInterface)
	td.vmIDToFIPIDs = make(map[int][]int)
	td.fipIDToFIP = make(map[int]mysql.FloatingIP)

	td.vl2IDToPodIDs = make(map[int][]int)
	td.podIDToVIFIDs = make(map[int][]int)

	td.vl2IDToVGWIDs = make(map[int][]int)
	td.vgwIDToVGW = make(map[int]mysql.VRouter)
	td.vgwIDToVIFIDs = make(map[int][]int)
	td.vl2IDToNetIDs = make(map[int][]int)
	td.idToSubnet = make(map[int]mysql.Subnet)

	td.vl2IDToVIFIDs = make(map[int][]int)
	td.vifIDToWANIPs = make(map[int]map[string]struct{})
	td.vifIDToLANIPs = make(map[int]map[string]struct{})

	return td
}

func (td *NetworkToolData) Load() (err error) {
	td.networks, err = UnscopedFind[mysql.Network]()
	if err != nil {
		return err
	}

	domains, err := UnscopedSelect[mysql.Domain]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}

	regions, err := UnscopedSelect[mysql.Region]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}

	azs, err := UnscopedSelect[mysql.AZ]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range azs {
		td.azLcuuidToName[item.Lcuuid] = item.Name
	}

	vpcs, err := UnscopedSelect[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	vifs, err := UnscopedFind[mysql.VInterface]()
	if err != nil {
		return err
	}
	for _, vif := range vifs {
		td.vifIDToVIF[vif.ID] = vif
		td.vl2IDToVIFIDs[vif.NetworkID] = append(td.vl2IDToVIFIDs[vif.NetworkID], vif.ID)
		switch vif.DeviceType {
		case ctrlcommon.VIF_DEVICE_TYPE_VM:
			td.vmIDToVIFIDs[vif.DeviceID] = append(td.vmIDToVIFIDs[vif.DeviceID], vif.ID)
		case ctrlcommon.VIF_DEVICE_TYPE_POD:
			td.podIDToVIFIDs[vif.DeviceID] = append(td.podIDToVIFIDs[vif.DeviceID], vif.ID)
		case ctrlcommon.VIF_DEVICE_TYPE_VROUTER:
			td.vgwIDToVIFIDs[vif.DeviceID] = append(td.vgwIDToVIFIDs[vif.DeviceID], vif.ID)
		}
	}
	fips, err := UnscopedSelect[mysql.FloatingIP]([]string{"id", "vm_id", "vl2_id"})
	if err != nil {
		return err
	}
	for _, item := range fips {
		td.fipIDToFIP[item.ID] = item
		td.vmIDToFIPIDs[item.VMID] = append(td.vmIDToFIPIDs[item.VMID], item.ID)
	}
	vms, err := UnscopedSelect[mysql.VM]([]string{"id"})
	if err != nil {
		return err
	}
	vl2IDToVMIDMap := make(map[int]map[int]struct{})
	for _, item := range vms {
		for vifID := range td.vmIDToVIFIDs[item.ID] {
			vif, ok := td.vifIDToVIF[vifID]
			if !ok {
				continue
			}
			if vl2IDToVMIDMap[vif.NetworkID] == nil {
				vl2IDToVMIDMap[vif.NetworkID] = make(map[int]struct{})
			}
			vl2IDToVMIDMap[vif.NetworkID][item.ID] = struct{}{}
		}
		for fipID := range td.vmIDToFIPIDs[item.ID] {
			fip, ok := td.fipIDToFIP[fipID]
			if !ok || fip.NetworkID == 0 {
				continue
			}
			if vl2IDToVMIDMap[fip.NetworkID] == nil {
				vl2IDToVMIDMap[fip.NetworkID] = make(map[int]struct{})
			}
			vl2IDToVMIDMap[fip.NetworkID][item.ID] = struct{}{}
		}
	}
	td.vl2IDToVMIDs = convertMapToSlice(vl2IDToVMIDMap)

	pods, err := UnscopedSelect[mysql.Pod]([]string{"id"})
	if err != nil {
		return err
	}
	vl2IDToPodIDs := make(map[int]map[int]struct{})
	for _, item := range pods {
		for vifID := range td.podIDToVIFIDs[item.ID] {
			vif := td.vifIDToVIF[vifID]
			if vl2IDToPodIDs[vif.NetworkID] == nil {
				vl2IDToPodIDs[vif.NetworkID] = make(map[int]struct{})
			}
			vl2IDToPodIDs[vif.NetworkID][item.ID] = struct{}{}
		}
	}
	td.vl2IDToPodIDs = convertMapToSlice(vl2IDToPodIDs)

	vgws, err := UnscopedSelect[mysql.VRouter]([]string{"id"})
	if err != nil {
		return err
	}
	vl2IDToVGWIDs := make(map[int]map[int]struct{})
	for _, item := range vgws {
		td.vgwIDToVGW[item.ID] = item
		for _, vifID := range td.vgwIDToVIFIDs[item.ID] {
			vif := td.vifIDToVIF[vifID]
			if vl2IDToVGWIDs[vif.NetworkID] == nil {
				vl2IDToVGWIDs[vif.NetworkID] = make(map[int]struct{})
			}
			vl2IDToVGWIDs[vif.NetworkID][item.ID] = struct{}{}
		}
	}
	td.vl2IDToVGWIDs = convertMapToSlice(vl2IDToVGWIDs)

	subnets, err := UnscopedFind[mysql.Subnet]()
	if err != nil {
		return err
	}
	for _, item := range subnets {
		td.idToSubnet[item.ID] = item
		td.vl2IDToNetIDs[item.NetworkID] = append(td.vl2IDToNetIDs[item.NetworkID], item.ID)
	}

	wanIPs, err := UnscopedSelect[mysql.WANIP]([]string{"vifid", "ip"})
	if err != nil {
		return err
	}
	for _, item := range wanIPs {
		if td.vifIDToWANIPs[item.VInterfaceID] == nil {
			td.vifIDToWANIPs[item.VInterfaceID] = make(map[string]struct{})
		}
		td.vifIDToWANIPs[item.VInterfaceID][item.IP] = struct{}{}
	}
	lanIPs, err := UnscopedSelect[mysql.LANIP]([]string{"vifid", "ip"})
	if err != nil {
		return err
	}
	for _, item := range lanIPs {
		if td.vifIDToLANIPs[item.VInterfaceID] == nil {
			td.vifIDToLANIPs[item.VInterfaceID] = make(map[string]struct{})
		}
		td.vifIDToLANIPs[item.VInterfaceID][item.IP] = struct{}{}
	}

	return nil
}
