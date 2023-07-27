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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"golang.org/x/exp/slices"
)

type VM struct {
	DataProvider
	dataTool *vmToolData
}

func NewVM() *VM {
	dp := &VM{newDataProvider(ctrlrcommon.RESOURCE_TYPE_VM_EN), new(vmToolData)}
	dp.setGenerator(dp)
	return dp
}

func (v *VM) generate() (data []common.ResponseElem, err error) {
	err = v.dataTool.Init().Load()
	for _, item := range v.dataTool.vms {
		data = append(data, v.generateOne(item))
	}
	return
}

func (v *VM) generateOne(item mysql.VM) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["DOMAIN_NAME"] = v.dataTool.domainLcuuidToName[item.Domain]
	d["REGION_NAME"] = v.dataTool.regionLcuuidToName[item.Region]
	d["AZ_NAME"] = v.dataTool.azLcuuidToName[item.AZ]
	d["EPC_NAME"] = v.dataTool.vpcIDToName[item.VPCID]
	hostInfo := v.dataTool.hostIPToInfo[item.LaunchServer]
	d["HOST_ID"] = hostInfo.id
	d["HOST_NAME"] = hostInfo.name
	podNodeInfo := v.dataTool.vmIDToPodNodeInfo[item.ID]
	d["POD_NODE_ID"] = podNodeInfo.id
	d["POD_NODE_NAME"] = podNodeInfo.name
	d["SECURITY_GROUPS"] = v.dataTool.vmIDToSecurityGroups[item.ID]
	d["SECURITY_GROUP_COUNT"] = len(v.dataTool.vmIDToSecurityGroups[item.ID])
	d["SUBNETS"] = v.dataTool.vmIDToNetworkInfos[item.ID]
	d["WAN_IPS"] = v.dataTool.vmIDToWANIPs[item.ID]
	d["LAN_IPS"] = v.dataTool.vmIDToLANIPs[item.ID]
	d["VIP"] = v.dataTool.vmIDToVIP[item.ID]
	allIPs := v.dataTool.vmIDToWANIPs[item.ID]
	allIPs = append(allIPs, v.dataTool.vmIDToLANIPs[item.ID]...)
	if vip, ok := v.dataTool.vmIDToVIP[item.ID]; ok {
		allIPs = append(allIPs, vip)
	}
	d["ALL_IPS"] = allIPs
	d["INTERFACES"] = v.dataTool.vmIDToVInterfaceInfos[item.ID]
	d["INTERFACE_COUNT"] = len(v.dataTool.vmIDToVInterfaceInfos[item.ID])
	for k, v := range v.getVTapInfo(item) {
		d[k] = v
	}

	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

func (v *VM) getVTapInfo(vm mysql.VM) map[string]interface{} {
	vtap, ok := v.dataTool.idToVTap[v.dataTool.vmIDToVTapID[vm.ID]]
	if ok && vtap.Type == ctrlrcommon.VTAP_TYPE_WORKLOAD_V {
		return convertToVTapInfo(vtap)
	}
	hostInfo, ok := v.dataTool.hostIPToInfo[vm.LaunchServer]
	if ok {
		vtap, ok = v.dataTool.idToVTap[v.dataTool.hostIDToVTapID[hostInfo.id]]
		if ok {
			return convertToVTapInfo(vtap)
		}
	}
	if vtap == nil {
		podNodeInfo, ok := v.dataTool.vmIDToPodNodeInfo[vm.ID]
		if ok {
			vtap, ok = v.dataTool.idToVTap[v.dataTool.podNodeIDToVTapID[podNodeInfo.id]]
		}
	}
	return convertToVTapInfo(vtap)
}

type vmToolData struct {
	vms []mysql.VM

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
	azLcuuidToName     map[string]string
	vpcIDToName        map[int]string
	networkIDToName    map[int]string

	hostIPToInfo map[string]idName

	vmIDToPodNodeInfo map[int]idName

	vmIDToNetworkInfos map[int][]map[string]interface{}

	vmIDToVIP map[int]string

	vmIDToSecurityGroups map[int][]map[string]interface{}

	vmIDToWANIPs          map[int][]string
	vmIDToLANIPs          map[int][]string
	vmIDToVInterfaceInfos map[int][]map[string]interface{}

	hostIDToVTapID    map[int]int
	vmIDToVTapID      map[int]int
	podNodeIDToVTapID map[int]int
	idToVTap          map[int]*mysql.VTap
}

func (td *vmToolData) Init() *vmToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.azLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)
	td.networkIDToName = make(map[int]string)

	td.hostIPToInfo = make(map[string]idName)

	td.vmIDToPodNodeInfo = make(map[int]idName)

	td.vmIDToNetworkInfos = make(map[int][]map[string]interface{})

	td.vmIDToVIP = make(map[int]string)

	td.vmIDToSecurityGroups = make(map[int][]map[string]interface{})

	td.vmIDToWANIPs = make(map[int][]string)
	td.vmIDToLANIPs = make(map[int][]string)
	td.vmIDToVInterfaceInfos = make(map[int][]map[string]interface{})

	td.hostIDToVTapID = make(map[int]int)
	td.vmIDToVTapID = make(map[int]int)
	td.podNodeIDToVTapID = make(map[int]int)
	td.idToVTap = make(map[int]*mysql.VTap)
	return td
}

func (td *vmToolData) Load() (err error) {
	td.vms, err = UnscopedOrderFind[mysql.VM]("created_at DESC")
	if err != nil {
		return err
	}

	domains, err := Select[mysql.Domain]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}

	regions, err := Select[mysql.Region]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}

	azs, err := Select[mysql.AZ]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range azs {
		td.azLcuuidToName[item.Lcuuid] = item.Name
	}

	vpcs, err := Select[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	hosts, err := Select[mysql.Host]([]string{"id", "ip"})
	if err != nil {
		return err
	}
	for _, item := range hosts {
		td.hostIPToInfo[item.IP] = idName{id: item.ID, name: item.Name}
	}

	vmSGs, err := Select[mysql.VMSecurityGroup]([]string{"vm_id", "sg_id"})
	if err != nil {
		return err
	}
	for _, item := range vmSGs {
		td.vmIDToSecurityGroups[item.VMID] = append(td.vmIDToSecurityGroups[item.VMID], map[string]interface{}{"ID": item.SecurityGroupID})
	}

	podNodes, err := Select[mysql.PodNode]([]string{"id", "name"})
	if err != nil {
		return err
	}
	podNodeIDToName := make(map[int]string)
	for _, item := range podNodes {
		podNodeIDToName[item.ID] = item.Name
	}
	vmPodNodeConns, err := Select[mysql.VMPodNodeConnection]([]string{"vm_id", "pod_node_id"})
	if err != nil {
		return err
	}
	for _, item := range vmPodNodeConns {
		td.vmIDToPodNodeInfo[item.VMID] = idName{id: item.PodNodeID, name: podNodeIDToName[item.PodNodeID]}
	}

	lbs, err := Select[mysql.LB]([]string{"id", "vip"})
	if err != nil {
		return err
	}
	lbIDToVIP := make(map[int]string)
	for _, item := range lbs {
		lbIDToVIP[item.ID] = item.VIP
	}
	lbVMConns, err := Select[mysql.LBVMConnection]([]string{"vm_id", "lb_id"})
	if err != nil {
		return err
	}
	for _, item := range lbVMConns {
		td.vmIDToVIP[item.VMID] = lbIDToVIP[item.LBID]
	}

	networks, err := Select[mysql.Network]([]string{"id", "name", "lcuuid"})
	if err != nil {
		return err
	}
	idToNetwork := make(map[int]mysql.Network)
	for _, item := range networks {
		idToNetwork[item.ID] = item
	}
	vifs, err := SelectWithQuery[mysql.VInterface]([]string{"id", "subnetid", "mac", "deviceid", "lcuuid", "state", "iftype"}, "devicetype = ?", ctrlrcommon.VIF_DEVICE_TYPE_VM)
	if err != nil {
		return err
	}
	vifIDs := make([]int, 0, len(vifs))
	for _, item := range vifs {
		vifIDs = append(vifIDs, item.ID)
	}
	wanIPs, err := SelectWithQuery[mysql.WANIP]([]string{"vifid", "ip"}, "vifid in (?)", vifIDs)
	if err != nil {
		return err
	}
	vifIDToWANIPs := make(map[int][]string)
	for _, item := range wanIPs {
		vifIDToWANIPs[item.VInterfaceID] = append(vifIDToWANIPs[item.VInterfaceID], item.IP)
	}
	lanIPs, err := SelectWithQuery[mysql.LANIP]([]string{"vifid", "ip"}, "vifid in (?)", vifIDs)
	if err != nil {
		return err
	}
	vifIDToLANIPs := make(map[int][]string)
	for _, item := range lanIPs {
		vifIDToLANIPs[item.VInterfaceID] = append(vifIDToLANIPs[item.VInterfaceID], item.IP)
	}
	vmIDToNetworkIDs := make(map[int][]int)
	for _, item := range vifs {
		network, ok := idToNetwork[item.NetworkID]
		if ok && !slices.Contains(vmIDToNetworkIDs[item.DeviceID], item.NetworkID) {
			vmIDToNetworkIDs[item.DeviceID] = append(vmIDToNetworkIDs[item.DeviceID], item.NetworkID)
			td.vmIDToNetworkInfos[item.DeviceID] = append(td.vmIDToNetworkInfos[item.DeviceID], map[string]interface{}{"ID": network.ID, "NAME": network.Name})
		}
		td.vmIDToWANIPs[item.DeviceID] = append(td.vmIDToWANIPs[item.DeviceID], vifIDToWANIPs[item.ID]...)
		td.vmIDToLANIPs[item.DeviceID] = append(td.vmIDToLANIPs[item.DeviceID], vifIDToLANIPs[item.ID]...)
		vifInfo := map[string]interface{}{
			"LCUUID":  item.Lcuuid,
			"STATE":   item.State,
			"MAC":     item.Mac,
			"IF_TYPE": "NONE",
		}
		if item.State == VIF_STATE_ATTACHED {
			ips := map[string]interface{}{
				"IPS":        []map[string]interface{}{},
				"VL2_LCUUID": network.Lcuuid,
				"VL2_ID":     item.NetworkID,
			}

			if item.Type == ctrlrcommon.VIF_TYPE_WAN {
				for _, ip := range vifIDToWANIPs[item.ID] {
					ips["IPS"] = append(ips["IPS"].([]map[string]interface{}), map[string]interface{}{"ADDRESS": ip})
				}
				vifInfo["IF_TYPE"] = "WAN"
				vifInfo["WAN"] = ips
			} else if item.Type == ctrlrcommon.VIF_TYPE_LAN {
				for _, ip := range vifIDToLANIPs[item.ID] {
					ips["IPS"] = append(ips["IPS"].([]map[string]interface{}), map[string]interface{}{"ADDRESS": ip})
				}
				vifInfo["IF_TYPE"] = "LAN"
				vifInfo["LAN"] = ips
			}
		}
		td.vmIDToVInterfaceInfos[item.DeviceID] = append(td.vmIDToVInterfaceInfos[item.DeviceID], vifInfo)
	}

	vtaps, err := Find[mysql.VTap]()
	if err != nil {
		return err
	}
	for _, item := range vtaps {
		td.idToVTap[item.ID] = item
		deviceType := ctrlrcommon.VTAP_TYPE_TO_DEVICE_TYPE[item.Type]
		if deviceType == ctrlrcommon.VIF_DEVICE_TYPE_HOST {
			td.hostIDToVTapID[item.LaunchServerID] = item.ID
		} else if deviceType == ctrlrcommon.VIF_DEVICE_TYPE_VM {
			td.vmIDToVTapID[item.LaunchServerID] = item.ID
		} else if deviceType == ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE {
			td.podNodeIDToVTapID[item.LaunchServerID] = item.ID
		}
	}

	return nil
}

type idName struct {
	id   int
	name string
}

const VIF_STATE_ATTACHED = 1
