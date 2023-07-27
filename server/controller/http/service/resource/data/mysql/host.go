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
)

type Host struct {
	DataProvider
	toolData *hostToolData
}

func NewHost() *Host {
	dp := &Host{newDataProvider(ctrlrcommon.RESOURCE_TYPE_HOST_EN), new(hostToolData)}
	dp.setGenerator(dp)
	return dp
}

func (h *Host) generate() (data []common.ResponseElem, err error) {
	err = h.toolData.init().load()
	for _, item := range h.toolData.hosts {
		data = append(data, h.generateOne(item))
	}
	return
}

func (h *Host) generateOne(item mysql.Host) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["MEM_TOTAL"] = d["MEM_TOTAL"].(float64) * 1024 * 1024
	d["REGION_NAME"] = h.toolData.regionLcuuidToName[item.Region]
	d["DOMAIN_NAME"] = h.toolData.domainLcuuidToName[item.Domain]
	d["AZ_NAME"] = h.toolData.azLcuuidToName[item.AZ]
	d["VM_COUNT"] = len(h.toolData.hostIPToVMIDs[item.IP])
	d["POD_COUNT"] = 0
	for _, vmID := range h.toolData.hostIPToVMIDs[item.IP] {
		if podNodeID, ok := h.toolData.vmIDToPodNodeID[vmID]; ok {
			d["POD_COUNT"] = d["POD_COUNT"].(int) + h.toolData.podNodeIDToPodCount[podNodeID]
		}
	}
	d["HOST_ROUTE_IPS"] = func(s []string) []string {
		r := make([]string, 0)
		for _, ip := range s {
			if ip != item.IP {
				r = append(r, ip)
			}
		}
		return r
	}(h.toolData.hostIDToIPs[item.ID])
	d["ALL_IPS"] = append([]string{item.IP}, h.toolData.hostIDToIPs[item.ID]...)
	d["INTERFACE_COUNT"] = h.toolData.hostIDToVInterfaceCount[item.ID]

	vtapInfo, ok := h.toolData.hostIDToVTapInfo[item.ID]
	if !ok {
		vtapInfo = convertToVTapInfo(nil)
	}
	for k, v := range vtapInfo {
		d[k] = v
	}

	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["SYNCED_AT"] = item.SyncedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

type hostToolData struct {
	hosts []mysql.Host

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
	azLcuuidToName     map[string]string

	hostIPToVMIDs       map[string][]int
	vmIDToPodNodeID     map[int]int
	podNodeIDToPodCount map[int]int

	hostIDToVInterfaceCount map[int]int
	hostIDToIPs             map[int][]string

	hostIDToVTapInfo map[int]map[string]interface{}
}

func (td *hostToolData) init() *hostToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.azLcuuidToName = make(map[string]string)

	td.hostIPToVMIDs = make(map[string][]int)
	td.vmIDToPodNodeID = make(map[int]int)
	td.podNodeIDToPodCount = make(map[int]int)

	td.hostIDToVInterfaceCount = make(map[int]int)
	td.hostIDToIPs = make(map[int][]string)

	td.hostIDToVTapInfo = make(map[int]map[string]interface{})
	return td
}

func (td *hostToolData) load() (err error) {
	td.hosts, err = UnscopedFind[mysql.Host]()
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

	vms, err := Select[mysql.VM]([]string{"id", "launch_server"})
	for _, item := range vms {
		td.hostIPToVMIDs[item.LaunchServer] = append(td.hostIPToVMIDs[item.LaunchServer], item.ID)
	}
	vmPodNodeConns, err := Select[mysql.VMPodNodeConnection]([]string{"vm_id", "pod_node_id"})
	if err != nil {
		return err
	}
	for _, item := range vmPodNodeConns {
		td.vmIDToPodNodeID[item.VMID] = item.PodNodeID
	}
	pods, err := Select[mysql.Pod]([]string{"pod_node_id"})
	if err != nil {
		return err
	}
	for _, item := range pods {
		td.podNodeIDToPodCount[item.PodNodeID]++
	}

	vifs, err := SelectWithQuery[mysql.VInterface]([]string{"id", "deviceid"}, "devicetype = ?", ctrlrcommon.VIF_DEVICE_TYPE_HOST)
	if err != nil {
		return err
	}
	vifIDs := make([]int, len(vifs))
	for _, item := range vifs {
		td.hostIDToVInterfaceCount[item.DeviceID]++
		vifIDs = append(vifIDs, item.ID)
	}
	wanIPs, err := SelectWithQuery[mysql.WANIP]([]string{"vifid", "ip"}, "vifid IN (?)", vifIDs)
	if err != nil {
		return err
	}
	for _, item := range wanIPs {
		td.hostIDToIPs[item.VInterfaceID] = append(td.hostIDToIPs[item.VInterfaceID], item.IP)
	}
	lanIPs, err := SelectWithQuery[mysql.LANIP]([]string{"vifid", "ip"}, "vifid IN (?)", vifIDs)
	if err != nil {
		return err
	}
	for _, item := range lanIPs {
		td.hostIDToIPs[item.VInterfaceID] = append(td.hostIDToIPs[item.VInterfaceID], item.IP)
	}

	vtaps, err := FindWhere[mysql.VTap]("type in (?)", []int{ctrlrcommon.VTAP_TYPE_KVM, ctrlrcommon.VTAP_TYPE_ESXI, ctrlrcommon.HOST_HTYPE_HYPER_V})
	if err != nil {
		return err
	}
	for _, item := range vtaps {
		td.hostIDToVTapInfo[item.ID] = convertToVTapInfo(item)
	}

	return nil
}

func convertToVTapInfo(vtap *mysql.VTap) map[string]interface{} {
	if vtap == nil {
		return map[string]interface{}{
			"VTAP_NAME":         nil,
			"VTAP_ID":           nil,
			"VTAP_LCUUID":       nil,
			"VTAP_TYPE":         nil,
			"VTAP_GROUP_LCUUID": nil,
			"VTAP_STATE":        nil,
		}
	}
	state := ctrlrcommon.VTAP_STATE_DISABLE
	if vtap.Enable == ctrlrcommon.VTAP_ENABLE_TRUE {
		state = vtap.State
	}
	return map[string]interface{}{
		"VTAP_NAME":         vtap.Name,
		"VTAP_ID":           vtap.ID,
		"VTAP_LCUUID":       vtap.Lcuuid,
		"VTAP_TYPE":         vtap.Type,
		"VTAP_GROUP_LCUUID": vtap.VtapGroupLcuuid,
		"VTAP_STATE":        state,
	}
}
