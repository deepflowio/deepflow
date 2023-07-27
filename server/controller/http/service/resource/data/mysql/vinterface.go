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

type VInterface struct {
	DataProvider
	toolData *vifToolData
}

func NewVInterface() *VInterface {
	dp := &VInterface{newDataProvider(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN), new(vifToolData)}
	dp.setGenerator(dp)
	return dp
}

func (h *VInterface) generate() (data []common.ResponseElem, err error) {
	err = h.toolData.init().load()
	for _, item := range h.toolData.vifs {
		data = append(data, h.generateOne(item))
	}
	return
}

func (h *VInterface) generateOne(item mysql.VInterface) common.ResponseElem {
	d := make(common.ResponseElem)
	d["ID"] = item.ID
	d["NAME"] = item.Name
	d["DOMAIN"] = item.Domain
	d["CREATE_METHOD"] = item.CreateMethod
	d["LCUUID"] = item.Lcuuid
	d["MAC"] = item.Mac
	d["EPC_ID"] = nil

	d["SUBNET_ID"] = item.NetworkID
	networkInfo := h.toolData.networkIDToInfo[item.NetworkID]
	d["SUBNET_NAME"] = networkInfo.name
	if networkInfo.vpcID != 0 {
		d["EPC_ID"] = networkInfo.vpcID
	}

	d["DEVICE_ID"] = item.DeviceID
	d["DEVICE_TYPE"] = item.DeviceType
	deviceInfo := h.getDeviceName(item.DeviceType, item.DeviceID)
	d["DEVICE_NAME"] = deviceInfo.name
	if deviceInfo.vpcID != 0 {
		d["EPC_ID"] = deviceInfo.vpcID
	}

	d["VM_HTYPE"] = nil
	if item.DeviceType == ctrlrcommon.VIF_DEVICE_TYPE_VM {
		d["VM_HTYPE"] = h.toolData.vmIDToType[item.DeviceID]
	}

	d["IPS"] = append(h.toolData.vifIDToWANIPs[item.ID], h.toolData.vifIDToLANIPs[item.ID]...)
	return d
}

func (v *VInterface) getDeviceName(deviceType, deviceID int) nameVPCID {
	switch deviceType {
	case ctrlrcommon.VIF_DEVICE_TYPE_HOST:
		return v.toolData.hostIDToInfo[deviceID]
	case ctrlrcommon.VIF_DEVICE_TYPE_VM:
		return v.toolData.vmIDToInfo[deviceID]
	case ctrlrcommon.VIF_DEVICE_TYPE_VROUTER:
		return v.toolData.vrouterIDToInfo[deviceID]
	case ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		return v.toolData.dhcpPortIDToInfo[deviceID]
	case ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		return v.toolData.natGatewayIDToInfo[deviceID]
	case ctrlrcommon.VIF_DEVICE_TYPE_LB:
		return v.toolData.lbIDToInfo[deviceID]
	case ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		return v.toolData.rdsInstanceIDToInfo[deviceID]
	case ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		return v.toolData.redisInstanceIDToInfo[deviceID]
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE:
		return v.toolData.podNodeIDToInfo[deviceID]
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		return v.toolData.podServiceIDToInfo[deviceID]
	case ctrlrcommon.VIF_DEVICE_TYPE_POD:
		return v.toolData.podIDToInfo[deviceID]
	default:
		log.Errorf("unknown device type: %d", deviceType)
		return nameVPCID{}
	}
}

type vifToolData struct {
	vifs []mysql.VInterface

	networkIDToInfo map[int]nameVPCID

	hostIDToInfo          map[int]nameVPCID
	vmIDToInfo            map[int]nameVPCID
	vrouterIDToInfo       map[int]nameVPCID
	dhcpPortIDToInfo      map[int]nameVPCID
	natGatewayIDToInfo    map[int]nameVPCID
	lbIDToInfo            map[int]nameVPCID
	rdsInstanceIDToInfo   map[int]nameVPCID
	redisInstanceIDToInfo map[int]nameVPCID
	podNodeIDToInfo       map[int]nameVPCID
	podServiceIDToInfo    map[int]nameVPCID
	podIDToInfo           map[int]nameVPCID

	vmIDToType map[int]int

	vifIDToWANIPs map[int][]string
	vifIDToLANIPs map[int][]string
}

func (td *vifToolData) init() *vifToolData {
	td.networkIDToInfo = make(map[int]nameVPCID)

	td.hostIDToInfo = make(map[int]nameVPCID)
	td.vmIDToInfo = make(map[int]nameVPCID)
	td.vrouterIDToInfo = make(map[int]nameVPCID)
	td.dhcpPortIDToInfo = make(map[int]nameVPCID)
	td.natGatewayIDToInfo = make(map[int]nameVPCID)
	td.lbIDToInfo = make(map[int]nameVPCID)
	td.rdsInstanceIDToInfo = make(map[int]nameVPCID)
	td.redisInstanceIDToInfo = make(map[int]nameVPCID)
	td.podNodeIDToInfo = make(map[int]nameVPCID)
	td.podServiceIDToInfo = make(map[int]nameVPCID)
	td.podIDToInfo = make(map[int]nameVPCID)

	td.vmIDToType = make(map[int]int)

	td.vifIDToWANIPs = make(map[int][]string)
	td.vifIDToLANIPs = make(map[int][]string)
	return td
}

func (td *vifToolData) load() (err error) {
	td.vifs, err = GetAll[mysql.VInterface]()
	if err != nil {
		return err
	}

	networks, err := Select[mysql.Network]([]string{"id", "name", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range networks {
		td.networkIDToInfo[item.ID] = nameVPCID{name: item.Name, vpcID: item.VPCID}
	}

	hosts, err := Select[mysql.Host]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range hosts {
		td.hostIDToInfo[item.ID] = nameVPCID{name: item.Name}
	}

	vms, err := Select[mysql.VM]([]string{"id", "name", "htype", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range vms {
		td.vmIDToInfo[item.ID] = nameVPCID{name: item.Name, vpcID: item.VPCID}
		td.vmIDToType[item.ID] = item.HType
	}

	vrouters, err := Select[mysql.VRouter]([]string{"id", "name", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range vrouters {
		td.vrouterIDToInfo[item.ID] = nameVPCID{name: item.Name, vpcID: item.VPCID}
	}

	dhcpPorts, err := Select[mysql.DHCPPort]([]string{"id", "name", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range dhcpPorts {
		td.dhcpPortIDToInfo[item.ID] = nameVPCID{name: item.Name, vpcID: item.VPCID}
	}

	natGateways, err := Select[mysql.NATGateway]([]string{"id", "name", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range natGateways {
		td.natGatewayIDToInfo[item.ID] = nameVPCID{name: item.Name, vpcID: item.VPCID}
	}

	lbs, err := Select[mysql.LB]([]string{"id", "name", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range lbs {
		td.lbIDToInfo[item.ID] = nameVPCID{name: item.Name, vpcID: item.VPCID}
	}

	rdsInstances, err := Select[mysql.RDSInstance]([]string{"id", "name", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range rdsInstances {
		td.rdsInstanceIDToInfo[item.ID] = nameVPCID{name: item.Name, vpcID: item.VPCID}
	}

	redisInstances, err := Select[mysql.RedisInstance]([]string{"id", "name", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range redisInstances {
		td.redisInstanceIDToInfo[item.ID] = nameVPCID{name: item.Name, vpcID: item.VPCID}
	}

	podNodes, err := Select[mysql.PodNode]([]string{"id", "name", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range podNodes {
		td.podNodeIDToInfo[item.ID] = nameVPCID{name: item.Name, vpcID: item.VPCID}
	}

	podServices, err := Select[mysql.PodService]([]string{"id", "name", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range podServices {
		td.podServiceIDToInfo[item.ID] = nameVPCID{name: item.Name, vpcID: item.VPCID}
	}

	pods, err := Select[mysql.Pod]([]string{"id", "name", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range pods {
		td.podIDToInfo[item.ID] = nameVPCID{name: item.Name, vpcID: item.VPCID}
	}

	wanIPs, err := Select[mysql.WANIP]([]string{"vifid", "ip"})
	if err != nil {
		return err
	}
	for _, item := range wanIPs {
		td.vifIDToWANIPs[item.VInterfaceID] = append(td.vifIDToWANIPs[item.VInterfaceID], item.IP)
	}
	lanIPs, err := Select[mysql.LANIP]([]string{"vifid", "ip"})
	if err != nil {
		return err
	}
	for _, item := range lanIPs {
		td.vifIDToLANIPs[item.VInterfaceID] = append(td.vifIDToLANIPs[item.VInterfaceID], item.IP)
	}
	return nil
}

type nameVPCID struct {
	name  string
	vpcID int
}
