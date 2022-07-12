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

package tagrecorder

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/model"
)

type ChVTapPort struct {
	UpdaterBase[mysql.ChVTapPort, VtapPortKey]
}

type DeviceInfo struct {
	DeviceID   int
	DeviceType int
	DeviceName string
	IconID     int
}

func NewChVTapPort() *ChVTapPort {
	updater := &ChVTapPort{
		UpdaterBase[mysql.ChVTapPort, VtapPortKey]{
			resourceTypeName: RESOURCE_TYPE_CH_VTAP_PORT,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (v *ChVTapPort) generateNewData() (map[VtapPortKey]mysql.ChVTapPort, bool) {
	var vTaps []mysql.VTap
	err := mysql.Db.Where("type = ?", common.VTAP_TYPE_DEDICATED).Find(&vTaps).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return nil, false
	}
	var hosts []mysql.Host
	err = mysql.Db.Where("htype = ?", common.HOST_HTYPE_GATEWAY).Find(&hosts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return nil, false
	}
	var vInterfaces []mysql.VInterface
	err = mysql.Db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_HOST).Find(&vInterfaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return nil, false
	}
	var chDevices []mysql.ChDevice
	err = mysql.Db.Find(&chDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return nil, false
	}
	deviceKeyToIconID := make(map[DeviceKey]int)
	for _, chDevice := range chDevices {
		deviceKeyToIconID[DeviceKey{DeviceID: chDevice.DeviceID, DeviceType: chDevice.DeviceType}] = chDevice.IconID
	}
	vtapVIFs, err := GetVTapInterfaces(nil)
	if err != nil {
		log.Error(errors.New("unable to get resource vtap-port"))
		return nil, false
	}
	keyToItem := make(map[VtapPortKey]mysql.ChVTapPort)
	if len(vtapVIFs) == 0 {
		log.Error(errors.New("no data in get vtap-port response"))
		return keyToItem, true
	}

	for _, data := range vtapVIFs {
		if data.TapMAC == "" {
			continue
		}
		tapMacSlice := strings.Split(data.TapMAC, ":")
		tapMacSlice = tapMacSlice[2:]
		tapMacStr := strings.Join(tapMacSlice, "")
		tapPort, err := strconv.ParseInt(tapMacStr, 16, 64)
		if err != nil {
			log.Error(err)
			return nil, false
		}
		var macPort int64
		if data.MAC == "" {
			macPort = 0
		} else {
			macSlice := strings.Split(data.MAC, ":")
			macSlice = macSlice[2:]
			macStr := strings.Join(macSlice, "")
			macPort, err = strconv.ParseInt(macStr, 16, 64)
			if err != nil {
				log.Error(err)
				return nil, false
			}
		}
		// 采集网卡+MAC
		vTapPort, ok := keyToItem[VtapPortKey{VtapID: data.VTapID, TapPort: tapPort}]
		if ok {
			vTapPort.MacType = CH_VTAP_PORT_TYPE_TAP_MAC
			nameSlice := strings.Split(vTapPort.Name, ", ")
			if len(nameSlice) >= CH_VTAP_PORT_NAME_MAX {
				if !strings.Contains(vTapPort.Name, ", ...") {
					vTapPort.Name = vTapPort.Name + ", ..."
				}
			} else {
				if !strings.Contains(vTapPort.Name, data.TapName) {
					vTapPort.Name = vTapPort.Name + ", " + data.TapName
				}
			}
			if vTapPort.DeviceID == 0 && vTapPort.DeviceType == 0 && data.DeviceID != 0 && data.DeviceType != 0 {
				vTapPort.DeviceID = data.DeviceID
				vTapPort.DeviceType = data.DeviceType
				vTapPort.DeviceName = data.DeviceName
				vTapPort.IconID = deviceKeyToIconID[DeviceKey{DeviceID: data.DeviceID, DeviceType: data.DeviceType}]
			}
		} else {
			keyToItem[VtapPortKey{VtapID: data.VTapID, TapPort: tapPort}] = mysql.ChVTapPort{
				VTapID:     data.VTapID,
				TapPort:    tapPort,
				MacType:    CH_VTAP_PORT_TYPE_TAP_MAC,
				Name:       data.TapName,
				DeviceID:   data.DeviceID,
				HostID:     data.DeviceHostID,
				DeviceType: data.DeviceType,
				DeviceName: data.DeviceName,
				HostName:   data.DeviceHostName,
				IconID:     deviceKeyToIconID[DeviceKey{DeviceID: data.DeviceID, DeviceType: data.DeviceType}],
			}
		}
		// 网卡+MAC
		if tapPort != macPort && macPort != 0 {
			vTapPort, ok := keyToItem[VtapPortKey{VtapID: data.VTapID, TapPort: macPort}]
			if ok {
				nameSlice := strings.Split(vTapPort.Name, ", ")
				if len(nameSlice) >= CH_VTAP_PORT_NAME_MAX {
					if !strings.Contains(vTapPort.Name, ", ...") {
						vTapPort.Name = vTapPort.Name + ", ..."
					}
				} else {
					if !strings.Contains(vTapPort.Name, data.Name) {
						vTapPort.Name = vTapPort.Name + ", " + data.Name
					}
				}
				if vTapPort.DeviceID == 0 && vTapPort.DeviceType == 0 && data.DeviceID != 0 && data.DeviceType != 0 {
					vTapPort.DeviceID = data.DeviceID
					vTapPort.DeviceType = data.DeviceType
					vTapPort.DeviceName = data.DeviceName
					vTapPort.IconID = deviceKeyToIconID[DeviceKey{DeviceID: data.DeviceID, DeviceType: data.DeviceType}]
				}
			} else {
				keyToItem[VtapPortKey{VtapID: data.VTapID, TapPort: macPort}] = mysql.ChVTapPort{
					VTapID:     data.VTapID,
					TapPort:    macPort,
					MacType:    CH_VTAP_PORT_TYPE_TAP_MAC,
					Name:       data.Name,
					DeviceID:   data.DeviceID,
					HostID:     data.DeviceHostID,
					DeviceType: data.DeviceType,
					DeviceName: data.DeviceName,
					HostName:   data.DeviceHostName,
					IconID:     deviceKeyToIconID[DeviceKey{DeviceID: data.DeviceID, DeviceType: data.DeviceType}],
				}
			}
		}
	}

	vTapIDToDeviceInfo, ok := v.generateVtapDeviceInfo()
	if !ok {
		return nil, false
	}
	for vTapID, deviceInfo := range vTapIDToDeviceInfo {
		vTapPort, ok := keyToItem[VtapPortKey{VtapID: vTapID, TapPort: 0}]
		if ok {
			nameSlice := strings.Split(vTapPort.Name, ", ")
			if len(nameSlice) >= CH_VTAP_PORT_NAME_MAX {
				if !strings.Contains(vTapPort.Name, ", ...") {
					vTapPort.Name = vTapPort.Name + ", ..."
				}
			} else if !common.IsValueInSliceString("lo", nameSlice) {
				vTapPort.Name = strings.Join([]string{"lo", vTapPort.Name}, ", ")
			}
			if vTapPort.DeviceID == 0 && vTapPort.DeviceType == 0 && deviceInfo.DeviceID != 0 && deviceInfo.DeviceType != 0 {
				vTapPort.DeviceID = deviceInfo.DeviceID
				vTapPort.DeviceType = deviceInfo.DeviceType
				vTapPort.DeviceName = deviceInfo.DeviceName
				vTapPort.IconID = deviceInfo.IconID
			}
		} else {
			keyToItem[VtapPortKey{VtapID: vTapID, TapPort: 0}] = mysql.ChVTapPort{
				VTapID:     vTapID,
				TapPort:    0,
				MacType:    0,
				Name:       "lo",
				DeviceID:   deviceInfo.DeviceID,
				DeviceType: deviceInfo.DeviceType,
				DeviceName: deviceInfo.DeviceName,
				IconID:     deviceInfo.IconID,
			}
		}
	}

	for _, host := range hosts {
		for _, vInterface := range vInterfaces {
			if host.ID == vInterface.DeviceID {
				macSlice := strings.Split(vInterface.Mac, ":")
				macSlice = macSlice[2:]
				macStr := strings.Join(macSlice, "")
				tapPort, err := strconv.ParseInt(macStr, 16, 64)
				if err != nil {
					log.Error(err)
					return nil, false
				}
				for _, vTap := range vTaps {
					if vTap.AZ == host.AZ {
						keyToItem[VtapPortKey{VtapID: vTap.ID, TapPort: tapPort}] = mysql.ChVTapPort{
							VTapID:   vTap.ID,
							TapPort:  tapPort,
							Name:     vInterface.Name + " " + host.Name,
							HostID:   host.ID,
							HostName: host.Name,
							IconID:   deviceKeyToIconID[DeviceKey{DeviceID: host.ID, DeviceType: common.VIF_DEVICE_TYPE_HOST}],
						}
					}
				}
			}
		}
	}
	return keyToItem, true
}

func (v *ChVTapPort) generateVtapDeviceInfo() (map[int]DeviceInfo, bool) {
	vTapIDToDeviceInfo := make(map[int]DeviceInfo)
	var hosts []mysql.Host
	err := mysql.Db.Find(&hosts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return vTapIDToDeviceInfo, false
	}
	var vms []mysql.VM
	err = mysql.Db.Find(&vms).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return vTapIDToDeviceInfo, false
	}
	var podNodes []mysql.PodNode
	err = mysql.Db.Find(&podNodes).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return vTapIDToDeviceInfo, false
	}
	var hostChDevices []mysql.ChDevice
	err = mysql.Db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_HOST).Find(&hostChDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return vTapIDToDeviceInfo, false
	}
	var vmChDevices []mysql.ChDevice
	err = mysql.Db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_VM).Find(&vmChDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return vTapIDToDeviceInfo, false
	}
	var podNodeChDevices []mysql.ChDevice
	err = mysql.Db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_POD_NODE).Find(&podNodeChDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return vTapIDToDeviceInfo, false
	}
	var vTaps []mysql.VTap
	err = mysql.Db.Find(&vTaps).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return vTapIDToDeviceInfo, false
	}

	hostIDToName := make(map[int]string)
	hostIDToIconID := make(map[int]int)
	for _, host := range hosts {
		hostIDToName[host.ID] = host.Name
	}
	for _, hostChDevice := range hostChDevices {
		hostIDToIconID[hostChDevice.DeviceID] = hostChDevice.IconID
	}
	vmIDToName := make(map[int]string)
	vmIDToIconID := make(map[int]int)
	for _, vm := range vms {
		vmIDToName[vm.ID] = vm.Name
	}
	for _, vmChDevice := range vmChDevices {
		vmIDToIconID[vmChDevice.DeviceID] = vmChDevice.IconID
	}
	podNodeIDToName := make(map[int]string)
	podNodeIDToIconID := make(map[int]int)
	for _, podNode := range podNodes {
		podNodeIDToName[podNode.ID] = podNode.Name
	}
	for _, podNodeChDevice := range podNodeChDevices {
		podNodeIDToIconID[podNodeChDevice.DeviceID] = podNodeChDevice.IconID
	}

	for _, vTap := range vTaps {
		if vTap.LaunchServerID == 0 {
			continue
		}
		if vTap.Type == common.VTAP_TYPE_KVM || vTap.Type == common.VTAP_TYPE_EXSI || vTap.Type == common.VTAP_TYPE_HYPER_V {
			vTapIDToDeviceInfo[vTap.ID] = DeviceInfo{
				DeviceType: common.VIF_DEVICE_TYPE_HOST,
				DeviceID:   vTap.LaunchServerID,
				DeviceName: hostIDToName[vTap.LaunchServerID],
				IconID:     hostIDToIconID[vTap.LaunchServerID],
			}
		} else if vTap.Type == common.VTAP_TYPE_WORKLOAD_V || vTap.Type == common.VTAP_TYPE_WORKLOAD_P {
			vTapIDToDeviceInfo[vTap.ID] = DeviceInfo{
				DeviceType: common.VIF_DEVICE_TYPE_VM,
				DeviceID:   vTap.LaunchServerID,
				DeviceName: vmIDToName[vTap.LaunchServerID],
				IconID:     vmIDToIconID[vTap.LaunchServerID],
			}
		} else if vTap.Type == common.VTAP_TYPE_POD_HOST || vTap.Type == common.VTAP_TYPE_POD_VM {
			vTapIDToDeviceInfo[vTap.ID] = DeviceInfo{
				DeviceType: common.VIF_DEVICE_TYPE_POD_NODE,
				DeviceID:   vTap.LaunchServerID,
				DeviceName: podNodeIDToName[vTap.LaunchServerID],
				IconID:     podNodeIDToIconID[vTap.LaunchServerID],
			}
		}
	}
	return vTapIDToDeviceInfo, true
}

func (v *ChVTapPort) generateKey(dbItem mysql.ChVTapPort) VtapPortKey {
	return VtapPortKey{VtapID: dbItem.VTapID, TapPort: dbItem.TapPort}
}

func (v *ChVTapPort) generateUpdateInfo(oldItem, newItem mysql.ChVTapPort) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	oldItemMap := make(map[string]interface{})
	newItemMap := make(map[string]interface{})
	oldItemStr, err := json.Marshal(oldItem)
	if err != nil {
		return nil, false
	}
	newItemStr, err := json.Marshal(newItem)
	if err != nil {
		return nil, false
	}
	err = json.Unmarshal(oldItemStr, &oldItemMap)
	if err != nil {
		return nil, false
	}
	err = json.Unmarshal(newItemStr, &newItemMap)
	if err != nil {
		return nil, false
	}
	for oldKey, oldValue := range oldItemMap {
		if oldValue != newItemMap[oldKey] {
			updateInfo[strings.ToLower(oldKey)] = newItemMap[oldKey]
		}
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func GetVTapInterfaces(filter map[string]interface{}) ([]model.VTapInterface, error) {
	var vtapVIFs []model.VTapInterface
	var genesisVIFs []*mysql.GoGenesisVInterface
	db := mysql.Db
	if _, ok := filter["name"]; ok {
		db = db.Where("name = ?", filter["name"])
	}
	if err := db.Select("name", "mac", "tap_name", "tap_mac", "vtap_id", "host_ip").Find(&genesisVIFs).Error; err != nil {
		log.Error(dbQueryResourceFailed("genesis_vinterface", err))
		return nil, err
	}

	// generate tool dataset
	var vtaps []*mysql.VTap
	if err := mysql.Db.Find(&vtaps).Error; err != nil {
		log.Error(dbQueryResourceFailed("vtap", err))
		return nil, err
	}
	idToVTap := make(map[int]*mysql.VTap)
	for _, vtap := range vtaps {
		idToVTap[vtap.ID] = vtap
	}

	var vifs []*mysql.VInterface
	if err := mysql.Db.Select("mac", "deviceid", "devicetype").Find(&vifs).Error; err != nil {
		log.Error(dbQueryResourceFailed("vinterface", err))
		return nil, err
	}
	macToVIFs := make(map[string][]*mysql.VInterface)
	for _, vif := range vifs {
		macToVIFs[vif.Mac] = append(macToVIFs[vif.Mac], vif)
	}

	var hosts []*mysql.Host
	if err := mysql.Db.Select("id", "name").Find(&hosts).Error; err != nil {
		log.Error(dbQueryResourceFailed("host_device", err))
		return nil, err
	}
	hostIDToName := make(map[int]string)
	hostIPToID := make(map[string]int)
	for _, host := range hosts {
		hostIDToName[host.ID] = host.Name
	}

	var vms []*mysql.VM
	if err := mysql.Db.Select("id", "name", "launch_server").Find(&vms).Error; err != nil {
		log.Error(dbQueryResourceFailed("vm", err))
		return nil, err
	}
	vmIDToName := make(map[int]string)
	vmIDToLaunchServer := make(map[int]string)
	for _, vm := range vms {
		vmIDToName[vm.ID] = vm.Name
		vmIDToLaunchServer[vm.ID] = vm.LaunchServer
	}

	var podNodes []*mysql.PodNode
	if err := mysql.Db.Select("id", "name").Find(&podNodes).Error; err != nil {
		log.Error(dbQueryResourceFailed("pod_node", err))
		return nil, err
	}
	podNodeIDToName := make(map[int]string)
	for _, podNode := range podNodes {
		podNodeIDToName[podNode.ID] = podNode.Name
	}

	var vmPodNodeConns []*mysql.VMPodNodeConnection
	if err := mysql.Db.Find(&vmPodNodeConns).Error; err != nil {
		log.Error(dbQueryResourceFailed("vm_pod_node_connection", err))
		return nil, err
	}
	vmIDToPodNodeID := make(map[int]int)
	podNodeIDToVMID := make(map[int]int)
	for _, conn := range vmPodNodeConns {
		vmIDToPodNodeID[conn.VMID] = conn.PodNodeID
		podNodeIDToVMID[conn.PodNodeID] = conn.VMID
	}

	vtapTypeToDeviceType := map[int]int{
		common.VTAP_TYPE_KVM:        common.VIF_DEVICE_TYPE_HOST,
		common.VTAP_TYPE_EXSI:       common.VIF_DEVICE_TYPE_HOST,
		common.VTAP_TYPE_WORKLOAD_V: common.VIF_DEVICE_TYPE_VM,
		common.VTAP_TYPE_WORKLOAD_P: common.VIF_DEVICE_TYPE_VM,
		common.VTAP_TYPE_POD_HOST:   common.VIF_DEVICE_TYPE_POD_NODE,
		common.VTAP_TYPE_POD_VM:     common.VIF_DEVICE_TYPE_POD_NODE,
		common.VTAP_TYPE_HYPER_V:    common.VIF_DEVICE_TYPE_HOST,
	}

	for _, gVIF := range genesisVIFs {
		vtapVIF := model.VTapInterface{
			Name:    gVIF.Name,
			MAC:     gVIF.MAC,
			TapName: gVIF.TapName,
			TapMAC:  gVIF.TapMAC,
			VTapID:  gVIF.VTapID,
			HostIP:  gVIF.HostIP,
		}
		vtap, ok := idToVTap[vtapVIF.VTapID]
		if ok {
			vtapVIF.VTapLaunchServer = vtap.LaunchServer
			vtapVIF.VTapLaunchServerID = vtap.LaunchServerID
			vtapVIF.VTapType = vtap.Type
			vtapVIF.VTapName = vtap.Name

			macVIFs := macToVIFs[vtapVIF.MAC]
			if len(macVIFs) > 0 {
				var macVIF *mysql.VInterface
				if len(macVIFs) == 1 {
					macVIF = macVIFs[0]
				} else {
					deviceType := vtapTypeToDeviceType[vtapVIF.VTapType]
					for _, mv := range macVIFs {
						if mv.DeviceType == deviceType {
							macVIF = mv
							break
						}
					}
				}
				vtapVIF.DeviceType = macVIF.DeviceType
				vtapVIF.DeviceID = macVIF.DeviceID
				if vtapVIF.DeviceType == common.VIF_DEVICE_TYPE_HOST {
					vtapVIF.DeviceName = hostIDToName[vtapVIF.DeviceID]
				} else if vtapVIF.DeviceType == common.VIF_DEVICE_TYPE_VM {
					if vmIDToPodNodeID[vtapVIF.DeviceID] != 0 {
						vtapVIF.DeviceName = podNodeIDToName[vtapVIF.DeviceID]
					} else {
						vtapVIF.DeviceName = vmIDToName[vtapVIF.DeviceID]
					}
					vtapVIF.DeviceHostID = hostIPToID[vmIDToLaunchServer[vtapVIF.DeviceID]]
					vtapVIF.DeviceHostName = hostIDToName[vtapVIF.DeviceHostID]
				} else if vtapVIF.DeviceType == common.VIF_DEVICE_TYPE_POD_NODE {
					vtapVIF.DeviceName = podNodeIDToName[vtapVIF.DeviceID]
					vtapVIF.DeviceHostID = hostIPToID[vmIDToLaunchServer[podNodeIDToVMID[vtapVIF.DeviceID]]]
					vtapVIF.DeviceHostName = hostIDToName[vtapVIF.DeviceHostID]
				}
			}
		}
		vtapVIFs = append(vtapVIFs, vtapVIF)
	}
	return vtapVIFs, nil
}
