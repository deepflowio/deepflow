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

	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type AllIP struct {
	DataProvider
	dataTool *AllIPToolData
}

type AllIPToolData struct {
	wanIP *WANIP
	lanIP *LANIP

	vl2IDAndIPToFloatingIP map[string]mysql.FloatingIP
	idToVIF                map[int]mysql.VInterface
	idToVGW                map[int]mysql.VRouter

	vmIDToConnNatGatewayID map[int]int
	idToNatGateWay         map[int]mysql.NATGateway

	vmIDToConnLBID map[int]int
	idToLB         map[int]mysql.LB

	vmIDToPodNodeID map[int]int
	idToPodNode     map[int]mysql.PodNode

	lbIDToConnVMIDs map[int][]int
	idToVM          map[int]mysql.VM

	podNodeIDToVMID map[int]int
}

func (td *AllIPToolData) Init() *AllIPToolData {
	td.vl2IDAndIPToFloatingIP = make(map[string]mysql.FloatingIP)
	td.idToVIF = make(map[int]mysql.VInterface)
	td.idToVGW = make(map[int]mysql.VRouter)

	td.vmIDToConnNatGatewayID = make(map[int]int)
	td.idToNatGateWay = make(map[int]mysql.NATGateway)

	td.vmIDToConnLBID = make(map[int]int)
	td.idToLB = make(map[int]mysql.LB)

	td.vmIDToPodNodeID = make(map[int]int)
	td.idToPodNode = make(map[int]mysql.PodNode)

	td.lbIDToConnVMIDs = make(map[int][]int)
	td.idToVM = make(map[int]mysql.VM)

	td.podNodeIDToVMID = make(map[int]int)

	return td
}

func (td *AllIPToolData) Load() error {
	fips, err := UnscopedFind[mysql.FloatingIP]()
	if err != nil {
		return err
	}
	for _, item := range fips {
		td.vl2IDAndIPToFloatingIP[fmt.Sprintf("%d%s", item.NetworkID, item.IP)] = item
	}

	vifs, err := UnscopedFind[mysql.VInterface]()
	if err != nil {
		return err
	}
	for _, vif := range vifs {
		td.idToVIF[vif.ID] = vif
	}

	vgws, err := UnscopedFind[mysql.VRouter]()
	if err != nil {
		return err
	}
	for _, item := range vgws {
		td.idToVGW[item.ID] = item
	}

	natVMConns, err := UnscopedSelect[mysql.NATVMConnection]([]string{"id", "nat_id"})
	if err != nil {
		return err
	}
	for _, item := range natVMConns {
		td.vmIDToConnNatGatewayID[item.ID] = item.NATGatewayID
	}

	natGateways, err := UnscopedFind[mysql.NATGateway]()
	if err != nil {
		return err
	}
	for _, item := range natGateways {
		td.idToNatGateWay[item.ID] = item
	}

	lbVMConns, err := UnscopedFind[mysql.LBVMConnection]()
	if err != nil {
		return err
	}
	for _, item := range lbVMConns {
		td.vmIDToConnLBID[item.VMID] = item.LBID
		td.lbIDToConnVMIDs[item.LBID] = append(td.lbIDToConnVMIDs[item.LBID], item.VMID)
	}

	lbs, err := UnscopedFind[mysql.LB]()
	if err != nil {
		return err
	}
	for _, item := range lbs {
		td.idToLB[item.ID] = item
	}

	vmPodNodeConns, err := UnscopedSelect[mysql.VMPodNodeConnection]([]string{"id", "vm_id", "pod_node_id"})
	if err != nil {
		return err
	}
	for _, item := range vmPodNodeConns {
		td.vmIDToPodNodeID[item.VMID] = item.ID
		td.podNodeIDToVMID[item.PodNodeID] = item.VMID
	}

	podNodes, err := UnscopedFind[mysql.PodNode]()
	if err != nil {
		return err
	}
	for _, item := range podNodes {
		td.idToPodNode[item.ID] = item
	}

	vms, err := UnscopedFind[mysql.VM]()
	if err != nil {
		return err
	}
	for _, item := range vms {
		td.idToVM[item.ID] = item
	}

	return nil
}

func NewAllIP() *AllIP {
	dp := &AllIP{
		newDataProvider(ctrlcommon.RESOURCE_TYPE_ALL_IP_EN),
		&AllIPToolData{wanIP: NewWANIP(), lanIP: NewLANIP()},
	}
	dp.setGenerator(dp)
	return dp
}

func (p *AllIP) generate() ([]common.ResponseElem, error) {
	if err := p.dataTool.Init().Load(); err != nil {
		return nil, err
	}
	wanIP, err := p.dataTool.wanIP.generate()
	if err != nil {
		return nil, err
	}
	lanIP, err := p.dataTool.lanIP.generate()
	if err != nil {
		return nil, err
	}
	ips := mergeResponses(wanIP, lanIP)

	for _, ip := range ips {
		deviceType, ok := ip["DEVICE_TYPE"]
		if !ok {
			continue
		}
		if deviceType == ctrlcommon.VIF_DEVICE_TYPE_VM {
			if d := p.appendAdditionalVGW(ip); d != nil {
				ips = append(ips, d)
			}
			if d := p.appendAdditionalNatGateway(ip); d != nil {
				ips = append(ips, d)
			}
			if d := p.appendAdditionalLB(ip); d != nil {
				ips = append(ips, d)
			}
			if d := p.appendAdditionalPodNode(ip); d != nil {
				ips = append(ips, d)
			}
		} else if deviceType == ctrlcommon.VIF_DEVICE_TYPE_LB {
			if ds := p.appendAdditionalVMByLB(ip); ds != nil {
				ips = append(ips, ds...)
			}
			ips = append(ips, p.appendAdditionalVMByLB(ip)...)
		} else if deviceType == ctrlcommon.VIF_DEVICE_TYPE_POD_NODE {
			if d := p.appendAdditionalVMByPodNode(ip); d != nil {
				ips = append(ips, d)
			}
		}
	}

	return ips, nil
}

func (p *AllIP) appendAdditionalVGW(data common.ResponseElem) common.ResponseElem {
	_, ok1 := p.dataTool.vl2IDAndIPToFloatingIP[fmt.Sprintf("%d%s", data["SUBNET_ID"], data["IP"])]
	vif, ok2 := p.dataTool.idToVIF[data["VIFID"].(int)]
	if ok1 && ok2 && vif.DeviceType == ctrlcommon.VIF_DEVICE_TYPE_VROUTER {
		vgw, ok := p.dataTool.idToVGW[vif.DeviceID]
		if !ok {
			return nil
		}

		newData := deepCopyData(data)
		data["EPC_ID"] = float64(vgw.VPCID)
		data["DEVICE_ID"] = vgw.ID
		data["DEVICE_NAME"] = vgw.Name
		data["DEVICE_TYPE"] = ctrlcommon.VIF_DEVICE_TYPE_VROUTER
		data["ADDITIONAL"] = true
		return newData
	}
	return nil
}

func (p *AllIP) appendAdditionalNatGateway(data common.ResponseElem) common.ResponseElem {
	vmNatID, ok := p.dataTool.vmIDToConnNatGatewayID[data["DEVICE_ID"].(int)]
	if !ok {
		return nil
	}
	nat, ok := p.dataTool.idToNatGateWay[vmNatID]
	if !ok {
		return nil
	}

	newData := deepCopyData(data)
	newData["DEVICE_ID"] = nat.ID
	newData["DEVICE_NAME"] = nat.Name
	newData["DEVICE_TYPE"] = ctrlcommon.VIF_DEVICE_TYPE_NAT_GATEWAY
	newData["ADDITIONAL"] = true
	return newData
}

func (p *AllIP) appendAdditionalLB(data common.ResponseElem) common.ResponseElem {
	vmLBID := p.dataTool.vmIDToConnLBID[data["DEVICE_ID"].(int)]
	lb, ok := p.dataTool.idToLB[vmLBID]
	if !ok {
		return nil
	}

	newData := deepCopyData(data)
	newData["DEVICE_ID"] = lb.ID
	newData["DEVICE_NAME"] = lb.Name
	newData["DEVICE_TYPE"] = ctrlcommon.VIF_DEVICE_TYPE_LB
	newData["ADDITIONAL"] = true
	return newData
}

func (p *AllIP) appendAdditionalPodNode(data common.ResponseElem) common.ResponseElem {
	podNodeID := p.dataTool.vmIDToPodNodeID[data["DEVICE_ID"].(int)]
	podNode, ok := p.dataTool.idToPodNode[podNodeID]
	if !ok {
		return nil
	}

	newData := deepCopyData(data)
	newData["DEVICE_ID"] = podNode.ID
	newData["DEVICE_NAME"] = podNode.Name
	newData["DEVICE_TYPE"] = ctrlcommon.VIF_DEVICE_TYPE_POD_NODE
	newData["ADDITIONAL"] = true
	return newData
}

func (p *AllIP) appendAdditionalVMByLB(data common.ResponseElem) []common.ResponseElem {
	lb, ok := p.dataTool.idToLB[data["DEVICE_ID"].(int)]
	if !ok {
		return nil
	}
	var newDatas []common.ResponseElem
	if lb.VIP != "" && data["IP"] == lb.VIP {
		vmIDs := p.dataTool.lbIDToConnVMIDs[data["DEVICE_ID"].(int)]
		for _, vmID := range vmIDs {
			vm, ok := p.dataTool.idToVM[vmID]
			if !ok {
				continue
			}

			newData := deepCopyData(data)
			newData["DEVICE_ID"] = vm.ID
			newData["DEVICE_NAME"] = vm.Name
			newData["DEVICE_TYPE"] = ctrlcommon.VIF_DEVICE_TYPE_VM
			newData["ADDITIONAL"] = true
			newDatas = append(newDatas, newData)
		}
	}
	return newDatas
}

func (p *AllIP) appendAdditionalVMByPodNode(data common.ResponseElem) common.ResponseElem {
	vmID, ok := p.dataTool.podNodeIDToVMID[data["DEVICE_ID"].(int)]
	if !ok {
		return nil
	}
	vm, ok := p.dataTool.idToVM[vmID]
	if !ok {
		return nil
	}

	newData := deepCopyData(data)
	newData["DEVICE_ID"] = vm.ID
	newData["DEVICE_NAME"] = vm.Name
	newData["DEVICE_TYPE"] = ctrlcommon.VIF_DEVICE_TYPE_VM
	newData["ADDITIONAL"] = true
	return newData
}

func deepCopyData(data common.ResponseElem) common.ResponseElem {
	resp := make(common.ResponseElem)
	for k, v := range data {
		resp[k] = v
	}
	return resp
}
