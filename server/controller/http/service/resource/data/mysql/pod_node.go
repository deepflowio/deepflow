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
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

type PodNode struct {
	DataProvider
	dataTool *PodNodeToolData
}

func NewPodNode() *PodNode {
	dp := &PodNode{newDataProvider(ctrlcommon.RESOURCE_TYPE_POD_NODE_EN), new(PodNodeToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *PodNode) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.podNodes {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *PodNode) generateOne(item mysql.PodNode) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["MEM_TOTAL"] = item.MemTotal * 1024 * 1024
	if _, ok := d["VPC_ID"]; ok {
		d["EPC_ID"] = item.VPCID
		delete(d, "VPC_ID")
	}

	d["POD_COUNT"] = len(p.dataTool.podNodeIDToPodIDs[item.ID])
	d["EPC_NAME"] = p.dataTool.vpcIDToName[item.VPCID]
	d["AZ_NAME"] = p.dataTool.azLcuuidToName[item.AZ]
	d["POD_CLUSTER_NAME"] = p.dataTool.podClusterIDToName[item.PodClusterID]

	var ips []string
	for _, ip := range p.dataTool.podNodeIDToIPs[item.ID] {
		if ip == item.IP {
			continue
		}
		ips = append(ips, ip)
	}
	d["INNER_ROUTER_IPS"] = ips
	d["ALL_IPS"] = append(ips, item.IP)

	vmID := p.dataTool.podNodeIDToVMID[item.ID]
	d["VM_ID"] = vmID
	d["VM_NAME"] = p.dataTool.vmIDToName[vmID]

	vtap := p.dataTool.podNodeIDToVTap[item.ID]
	for k, v := range getVTapInfo(&vtap) {
		d[k] = v
	}
	if vtap.Type != 0 && vtap.Type == ctrlcommon.VTAP_TYPE_POD_VM {
		d["SERVER_TYPE"] = ctrlcommon.POD_NODE_SERVER_TYPE_VM
	} else if vmID != 0 {
		d["SERVER_TYPE"] = ctrlcommon.POD_NODE_SERVER_TYPE_VM
	}

	return d
}

type PodNodeToolData struct {
	podNodes []mysql.PodNode

	podNodeIDToPodIDs  map[int][]int
	vpcIDToName        map[int]string
	azLcuuidToName     map[string]string
	podClusterIDToName map[int]string

	podNodeIDToIPs    map[int][]string
	vifIDToLANIPs     map[int][]string
	vifIDToWANIPs     map[int][]string
	podNodeIDToVifIDs map[int][]int

	podNodeIDToVMID map[int]int
	vmIDToName      map[int]string

	podNodeIDToVTap map[int]mysql.VTap
}

func (td *PodNodeToolData) Init() *PodNodeToolData {
	td.podNodeIDToPodIDs = make(map[int][]int)
	td.vpcIDToName = make(map[int]string)
	td.azLcuuidToName = make(map[string]string)
	td.podClusterIDToName = make(map[int]string)

	td.podNodeIDToIPs = make(map[int][]string)
	td.vifIDToLANIPs = make(map[int][]string)
	td.vifIDToWANIPs = make(map[int][]string)
	td.podNodeIDToVifIDs = make(map[int][]int)

	td.podNodeIDToVMID = make(map[int]int)
	td.vmIDToName = make(map[int]string)

	td.podNodeIDToVTap = make(map[int]mysql.VTap)

	return td
}

func (td *PodNodeToolData) Load() (err error) {
	td.podNodes, err = UnscopedFind[mysql.PodNode]()
	if err != nil {
		return err
	}

	pods, err := UnscopedSelect[mysql.Pod]([]string{"id", "pod_node_id"})
	if err != nil {
		return err
	}
	for _, item := range pods {
		td.podNodeIDToPodIDs[item.PodNodeID] = append(td.podNodeIDToPodIDs[item.PodNodeID], item.ID)
	}

	vpcs, err := UnscopedSelect[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	azs, err := Select[mysql.AZ]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range azs {
		td.azLcuuidToName[item.Lcuuid] = item.Name
	}

	podClusters, err := UnscopedSelect[mysql.PodCluster]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range podClusters {
		td.podClusterIDToName[item.ID] = item.Name
	}

	// set podNodeIDToIPs
	lanIPs, err := UnscopedSelect[mysql.LANIP]([]string{"ip", "vifid"})
	if err != nil {
		return err
	}
	for _, lanIP := range lanIPs {
		vifID := lanIP.VInterfaceID
		td.vifIDToLANIPs[vifID] = append(td.vifIDToLANIPs[vifID], lanIP.IP)
	}
	wanIPs, err := UnscopedSelect[mysql.LANIP]([]string{"ip", "vifid"})
	if err != nil {
		return err
	}
	for _, wanIP := range wanIPs {
		vifID := wanIP.VInterfaceID
		td.vifIDToWANIPs[vifID] = append(td.vifIDToWANIPs[vifID], wanIP.IP)
	}
	vifs, err := SelectWithQuery[mysql.VInterface]([]string{"id", "deviceid"}, "devicetype=?", ctrlcommon.VIF_DEVICE_TYPE_POD_NODE)
	if err != nil {
		return err
	}
	for _, item := range vifs {
		td.podNodeIDToVifIDs[item.DeviceID] = append(td.podNodeIDToVifIDs[item.DeviceID], item.ID)
	}
	podNodeIDToIPMap := make(map[int]map[string]struct{})
	for _, podNode := range td.podNodes {
		for _, vifID := range td.podNodeIDToVifIDs[podNode.ID] {
			for _, lanIP := range td.vifIDToLANIPs[vifID] {
				if podNodeIDToIPMap[podNode.ID] == nil {
					podNodeIDToIPMap[podNode.ID] = make(map[string]struct{})
				}
				podNodeIDToIPMap[podNode.ID][lanIP] = struct{}{}
			}
			for _, wanIP := range td.vifIDToWANIPs[vifID] {
				if podNodeIDToIPMap[podNode.ID] == nil {
					podNodeIDToIPMap[podNode.ID] = make(map[string]struct{})
				}
				podNodeIDToIPMap[podNode.ID][wanIP] = struct{}{}
			}

		}
		if !utils.Find[string](td.podNodeIDToIPs[podNode.ID], podNode.IP) {
			if podNodeIDToIPMap[podNode.ID] == nil {
				podNodeIDToIPMap[podNode.ID] = make(map[string]struct{})
			}
			podNodeIDToIPMap[podNode.ID][podNode.IP] = struct{}{}
		}
	}
	td.podNodeIDToIPs = convertMapToSlice(podNodeIDToIPMap)

	vmPodNodeConns, err := UnscopedSelect[mysql.VMPodNodeConnection]([]string{"pod_node_id", "vm_id"})
	if err != nil {
		return err
	}
	for _, item := range vmPodNodeConns {
		td.podNodeIDToVMID[item.PodNodeID] = item.VMID
	}

	vms, err := UnscopedSelect[mysql.VM]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vms {
		td.vmIDToName[item.ID] = item.Name
	}

	vtaps, err := UnscopedSelect[mysql.VTap]([]string{"launch_server_id", "type", "id", "lcuuid",
		"vtap_group_lcuuid", "vtap_lcuuid", "name", "state", "enable"})
	for _, vtap := range vtaps {
		deviceType := ctrlcommon.VTAP_TYPE_TO_DEVICE_TYPE[vtap.Type]
		if deviceType == 0 || vtap.LaunchServerID == 0 {
			continue
		}
		if deviceType == ctrlcommon.VIF_DEVICE_TYPE_HOST ||
			deviceType == ctrlcommon.VIF_DEVICE_TYPE_VM {
			continue
		}

		td.podNodeIDToVTap[vtap.LaunchServerID] = vtap
	}

	return nil
}
