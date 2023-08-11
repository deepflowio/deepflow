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
	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type VPC struct {
	DataProvider
	dataTool *VPCToolData
}

func NewVPC() *VPC {
	dp := &VPC{newDataProvider(ctrlcommon.RESOURCE_TYPE_VPC_EN), new(VPCToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *VPC) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.vpcs {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *VPC) generateOne(item mysql.VPC) common.ResponseElem {
	d := MySQLModelToMap(item)

	d["DOMAIN_NAME"] = p.dataTool.domainLcuuidToName[item.Domain]
	d["DOMAIN_TYPE"] = p.dataTool.domainLcuuidToType[item.Domain]
	d["REGION_NAME"] = p.dataTool.regionLcuuidToName[item.Region]

	vl2IDs := p.dataTool.vpcIDToVL2IDs[item.ID]
	d["SUBNET_COUNT"] = len(vl2IDs)

	var subnets []interface{}
	sharedVL2IDs := p.dataTool.domainLcuuidToSharedVL2IDs[item.Domain]
	for _, vl2ID := range append(vl2IDs, sharedVL2IDs...) {
		vl2 := p.dataTool.vl2IDToVL2[vl2ID]
		if vl2.ID == 0 {
			continue
		}
		subnets = append(subnets, map[string]interface{}{
			"ID":     vl2.ID,
			"NAME":   vl2.Name,
			"SHARED": vl2.Shared,
		})
	}
	d["SUBNETS"] = subnets

	d["VM_COUNT"] = len(p.dataTool.vpcIDToVMIDs[item.ID])
	d["POD_COUNT"] = len(p.dataTool.vpcIDToPodIDs[item.ID])
	d["POD_NODE_COUNT"] = len(p.dataTool.vpcIDToPodNodeIDs[item.ID])
	d["WAN_IP_COUNT"] = len(p.dataTool.vpcIDToWANIPs[item.ID])

	return d
}

type VPCToolData struct {
	vpcs []mysql.VPC

	domainLcuuidToName map[string]string
	domainLcuuidToType map[string]int
	regionLcuuidToName map[string]string

	vpcIDToVL2IDs              map[int][]int
	domainLcuuidToSharedVL2IDs map[string][]int
	vl2IDToVL2                 map[int]mysql.Network

	vpcIDToVMIDs      map[int][]int
	vpcIDToPodIDs     map[int][]int
	vpcIDToPodNodeIDs map[int][]int

	vpcIDToWANIPs map[int][]string
}

func (td *VPCToolData) Init() *VPCToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.domainLcuuidToType = make(map[string]int)
	td.regionLcuuidToName = make(map[string]string)

	td.vpcIDToVL2IDs = make(map[int][]int)
	td.domainLcuuidToSharedVL2IDs = make(map[string][]int)
	td.vl2IDToVL2 = make(map[int]mysql.Network)

	td.vpcIDToVMIDs = make(map[int][]int)
	td.vpcIDToPodIDs = make(map[int][]int)
	td.vpcIDToPodNodeIDs = make(map[int][]int)

	td.vpcIDToWANIPs = make(map[int][]string)

	return td
}

func (td *VPCToolData) Load() (err error) {
	td.vpcs, err = UnscopedFind[mysql.VPC]()
	if err != nil {
		return err
	}

	domains, err := UnscopedSelect[mysql.Domain]([]string{"lcuuid", "name", "type"})
	if err != nil {
		return err
	}
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
		td.domainLcuuidToType[item.Lcuuid] = item.Type
	}

	regions, err := UnscopedSelect[mysql.Region]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}

	vl2s, err := UnscopedFind[mysql.Network]()
	if err != nil {
		return err
	}
	for _, item := range vl2s {
		td.vpcIDToVL2IDs[item.VPCID] = append(td.vpcIDToVL2IDs[item.VPCID], item.ID)
		if item.Shared {
			td.domainLcuuidToSharedVL2IDs[item.Domain] = append(td.domainLcuuidToSharedVL2IDs[item.Domain], item.ID)
		}
		td.vl2IDToVL2[item.ID] = item
	}

	vms, err := UnscopedSelect[mysql.VM]([]string{"id", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range vms {
		td.vpcIDToVMIDs[item.VPCID] = append(td.vpcIDToVMIDs[item.VPCID], item.ID)
	}

	pods, err := UnscopedSelect[mysql.Pod]([]string{"id", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range pods {
		td.vpcIDToPodIDs[item.VPCID] = append(td.vpcIDToPodIDs[item.VPCID], item.ID)
	}

	podNodes, err := UnscopedSelect[mysql.PodNode]([]string{"id", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range podNodes {
		td.vpcIDToPodNodeIDs[item.VPCID] = append(td.vpcIDToPodNodeIDs[item.VPCID], item.ID)
	}

	td.vpcIDToWANIPs, err = getVPCIDToWANIPs(td)
	if err != nil {
		return err
	}
	return nil
}

func getVPCIDToWANIPs(td *VPCToolData) (map[int][]string, error) {
	vpcIDToWANIPs := make(map[int][]string)

	wanIPs, err := UnscopedSelect[mysql.WANIP]([]string{"id", "vifid", "ip"})
	if err != nil {
		return nil, err
	}
	vifIDToWANIPMap := make(map[int]map[string]struct{})
	for _, wanIP := range wanIPs {
		if vifIDToWANIPMap[wanIP.VInterfaceID] == nil {
			vifIDToWANIPMap[wanIP.VInterfaceID] = make(map[string]struct{})
		}
		vifIDToWANIPMap[wanIP.VInterfaceID][wanIP.IP] = struct{}{}
	}
	vifIDToWANIPs := convertMapToSlice(vifIDToWANIPMap)

	var (
		vifIDToVIF              = make(map[int]mysql.VInterface)
		hostIDToVIFIDs          = make(map[int][]int)
		vgwIDToVIFIDs           = make(map[int][]int)
		vmIDToVIFIDs            = make(map[int][]int)
		dhcpPortIDToVIFIDs      = make(map[int][]int)
		natGatewayIDToVIFIDs    = make(map[int][]int)
		lbIDToVIFIDs            = make(map[int][]int)
		rdsInstanceIDToVIFIDs   = make(map[int][]int)
		redisInstanceIDToVIFIDs = make(map[int][]int)
		podNodeIDToVIFIDs       = make(map[int][]int)
		podServiceIDToVIFIDs    = make(map[int][]int)
		podIDToVIFIDs           = make(map[int][]int)
	)
	vifs, err := UnscopedFind[mysql.VInterface]()
	if err != nil {
		return nil, err
	}
	for _, vif := range vifs {
		vifIDToVIF[vif.ID] = vif
		switch vif.DeviceType {
		case ctrlcommon.VIF_DEVICE_TYPE_HOST:
			hostIDToVIFIDs[vif.DeviceID] = append(hostIDToVIFIDs[vif.DeviceID], vif.ID)
		case ctrlcommon.VIF_DEVICE_TYPE_VROUTER:
			vgwIDToVIFIDs[vif.DeviceID] = append(vgwIDToVIFIDs[vif.DeviceID], vif.ID)
		case ctrlcommon.VIF_DEVICE_TYPE_VM:
			vmIDToVIFIDs[vif.DeviceID] = append(vmIDToVIFIDs[vif.DeviceID], vif.ID)
		case ctrlcommon.VIF_DEVICE_TYPE_DHCP_PORT:
			dhcpPortIDToVIFIDs[vif.DeviceID] = append(dhcpPortIDToVIFIDs[vif.DeviceID], vif.ID)
		case ctrlcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
			natGatewayIDToVIFIDs[vif.DeviceID] = append(natGatewayIDToVIFIDs[vif.DeviceID], vif.ID)
		case ctrlcommon.VIF_DEVICE_TYPE_LB:
			lbIDToVIFIDs[vif.DeviceID] = append(lbIDToVIFIDs[vif.DeviceID], vif.ID)
		case ctrlcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
			rdsInstanceIDToVIFIDs[vif.DeviceID] = append(rdsInstanceIDToVIFIDs[vif.DeviceID], vif.ID)
		case ctrlcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
			redisInstanceIDToVIFIDs[vif.DeviceID] = append(redisInstanceIDToVIFIDs[vif.DeviceID], vif.ID)
		case ctrlcommon.VIF_DEVICE_TYPE_POD_NODE:
			podNodeIDToVIFIDs[vif.DeviceID] = append(podNodeIDToVIFIDs[vif.DeviceID], vif.ID)
		case ctrlcommon.VIF_DEVICE_TYPE_POD_SERVICE:
			podServiceIDToVIFIDs[vif.DeviceID] = append(podServiceIDToVIFIDs[vif.DeviceID], vif.ID)
		case ctrlcommon.VIF_DEVICE_TYPE_POD:
			podIDToVIFIDs[vif.DeviceID] = append(podIDToVIFIDs[vif.DeviceID], vif.ID)
		}
	}

	hosts, err := UnscopedSelect[mysql.Host]([]string{"id"})
	if err != nil {
		return nil, err
	}
	for _, item := range hosts {
		for _, vifID := range hostIDToVIFIDs[item.ID] {
			vif := vifIDToVIF[vifID]
			if vif.ID == 0 {
				continue
			}
			vl2 := td.vl2IDToVL2[vif.NetworkID]
			if vl2.ID == 0 {
				continue
			}

			wanIPs := vifIDToWANIPs[vifID]
			vpcIDToWANIPs[vl2.VPCID] = append(vpcIDToWANIPs[vl2.VPCID], wanIPs...)
		}
	}

	vgws, err := UnscopedSelect[mysql.VRouter]([]string{"id", "epc_id"})
	if err != nil {
		return nil, err
	}
	for _, item := range vgws {
		for _, vifID := range vgwIDToVIFIDs[item.ID] {
			vpcIDToWANIPs[item.VPCID] = append(vpcIDToWANIPs[item.VPCID], vifIDToWANIPs[vifID]...)
		}
	}

	vms, err := UnscopedSelect[mysql.VM]([]string{"id", "epc_id"})
	if err != nil {
		return nil, err
	}
	for _, item := range vms {
		for _, vifID := range vmIDToVIFIDs[item.ID] {
			vpcIDToWANIPs[item.VPCID] = append(vpcIDToWANIPs[item.VPCID], vifIDToWANIPs[vifID]...)
		}
	}

	dhcpPorts, err := UnscopedSelect[mysql.DHCPPort]([]string{"id", "epc_id"})
	if err != nil {
		return nil, err
	}
	for _, item := range dhcpPorts {
		for _, vifID := range dhcpPortIDToVIFIDs[item.ID] {
			vpcIDToWANIPs[item.VPCID] = append(vpcIDToWANIPs[item.VPCID], vifIDToWANIPs[vifID]...)
		}
	}

	natGateways, err := UnscopedSelect[mysql.NATGateway]([]string{"id", "epc_id"})
	if err != nil {
		return nil, err
	}
	for _, item := range natGateways {
		for _, vifID := range natGatewayIDToVIFIDs[item.ID] {
			vpcIDToWANIPs[item.VPCID] = append(vpcIDToWANIPs[item.VPCID], vifIDToWANIPs[vifID]...)
		}
	}

	lbs, err := UnscopedSelect[mysql.LB]([]string{"id", "epc_id"})
	if err != nil {
		return nil, err
	}
	for _, item := range lbs {
		for _, vifID := range lbIDToVIFIDs[item.ID] {
			vpcIDToWANIPs[item.VPCID] = append(vpcIDToWANIPs[item.VPCID], vifIDToWANIPs[vifID]...)
		}
	}

	rdsInstances, err := UnscopedSelect[mysql.RDSInstance]([]string{"id", "epc_id"})
	if err != nil {
		return nil, err
	}
	for _, item := range rdsInstances {
		for _, vifID := range rdsInstanceIDToVIFIDs[item.ID] {
			vpcIDToWANIPs[item.VPCID] = append(vpcIDToWANIPs[item.VPCID], vifIDToWANIPs[vifID]...)
		}
	}

	redisInstances, err := UnscopedSelect[mysql.RedisInstance]([]string{"id", "epc_id"})
	if err != nil {
		return nil, err
	}
	for _, item := range redisInstances {
		for _, vifID := range redisInstanceIDToVIFIDs[item.ID] {
			vpcIDToWANIPs[item.VPCID] = append(vpcIDToWANIPs[item.VPCID], vifIDToWANIPs[vifID]...)
		}
	}

	podNodes, err := UnscopedSelect[mysql.PodNode]([]string{"id", "epc_id"})
	if err != nil {
		return nil, err
	}
	for _, item := range podNodes {
		for _, vifID := range podNodeIDToVIFIDs[item.ID] {
			vpcIDToWANIPs[item.VPCID] = append(vpcIDToWANIPs[item.VPCID], vifIDToWANIPs[vifID]...)
		}
	}

	podServices, err := UnscopedSelect[mysql.PodService]([]string{"id", "epc_id"})
	if err != nil {
		return nil, err
	}
	for _, item := range podServices {
		for _, vifID := range podServiceIDToVIFIDs[item.ID] {
			vpcIDToWANIPs[item.VPCID] = append(vpcIDToWANIPs[item.VPCID], vifIDToWANIPs[vifID]...)
		}
	}

	pods, err := UnscopedSelect[mysql.Pod]([]string{"id", "epc_id"})
	if err != nil {
		return nil, err
	}
	for _, item := range pods {
		for _, vifID := range podIDToVIFIDs[item.ID] {
			vpcIDToWANIPs[item.VPCID] = append(vpcIDToWANIPs[item.VPCID], vifIDToWANIPs[vifID]...)
		}
	}

	return vpcIDToWANIPs, nil
}
