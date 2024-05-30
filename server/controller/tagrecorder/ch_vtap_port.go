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

package tagrecorder

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/vtap"
	"github.com/deepflowio/deepflow/server/controller/model"
)

const vTapPortNameLength = 256

type ChVTapPort struct {
	UpdaterComponent[mysql.ChVTapPort, VtapPortKey]
}

type DeviceInfo struct {
	DeviceID   int
	DeviceType int
	DeviceName string
	IconID     int
	TeamID     int
}

func NewChVTapPort() *ChVTapPort {
	updater := &ChVTapPort{
		newUpdaterComponent[mysql.ChVTapPort, VtapPortKey](
			RESOURCE_TYPE_CH_VTAP_PORT,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (v *ChVTapPort) generateNewData(db *mysql.DB) (map[VtapPortKey]mysql.ChVTapPort, bool) {
	var vTaps []mysql.VTap
	err := db.Where("type = ?", common.VTAP_TYPE_DEDICATED).Unscoped().Find(&vTaps).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return nil, false
	}
	var hosts []mysql.Host
	err = db.Where("htype = ?", common.HOST_HTYPE_GATEWAY).Unscoped().Find(&hosts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return nil, false
	}
	var vInterfaces []mysql.VInterface
	err = db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_HOST).Unscoped().Find(&vInterfaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return nil, false
	}
	var chDevices []mysql.ChDevice
	err = db.Unscoped().Find(&chDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return nil, false
	}
	deviceKeyToIconID := make(map[DeviceKey]int)
	for _, chDevice := range chDevices {
		deviceKeyToIconID[DeviceKey{DeviceID: chDevice.DeviceID, DeviceType: chDevice.DeviceType}] = chDevice.IconID
	}
	vtapVIFs, err := getVTapInterfaces(db.ORGID)
	if err != nil {
		log.Error(errors.New("unable to get resource vtap-port"))
		return nil, false
	}
	keyToItem := make(map[VtapPortKey]mysql.ChVTapPort)
	if len(vtapVIFs) == 0 {
		log.Info("no data in get vtap-port response")
		return keyToItem, true
	}

	for _, data := range vtapVIFs {
		if data.TapMAC == "" {
			log.Infof("invalid tap mac: %+v", data)
			continue
		}
		tapMacSlice := strings.Split(data.TapMAC, ":")
		if len(tapMacSlice) < 3 {
			log.Infof("invalid tap mac: %+v", data)
			continue
		}
		tapMacSlice = tapMacSlice[2:]
		tapMacStr := strings.Join(tapMacSlice, "")
		tapPort, err := strconv.ParseInt(tapMacStr, 16, 64)
		if err != nil {
			log.Errorf("format tap mac failed: %s, %+v, %v", tapMacStr, data, err)
			continue
		}
		var macPort int64
		if data.MAC == "" {
			log.Infof("no mac: %+v", data)
			macPort = 0
		} else {
			macSlice := strings.Split(data.MAC, ":")
			if len(macSlice) < 3 {
				log.Infof("invalid mac %s: %+v", data)
				continue
			}
			macSlice = macSlice[2:]
			macStr := strings.Join(macSlice, "")
			macPort, err = strconv.ParseInt(macStr, 16, 64)
			if err != nil {
				log.Errorf("format mac failed: %s, %+v, %v", macStr, data, err)
				continue
			}
		}

		// 采集网卡+MAC
		tapMacKey := VtapPortKey{VtapID: data.VTapID, TapPort: tapPort}
		log.Debugf("tap mac: %s, key: %+v", data.TapMAC, tapMacKey)
		vTapPort, ok := keyToItem[tapMacKey]
		if ok {
			vTapPort.MacType = CH_VTAP_PORT_TYPE_TAP_MAC
			nameSlice := sortVTapPortJoinedNames(&vTapPort)
			if len(nameSlice) >= CH_VTAP_PORT_NAME_MAX {
				if !strings.Contains(vTapPort.Name, ", ...") {
					vTapPort.Name = vTapPort.Name + ", ..."
				}
				log.Debugf("pass name: %s (id: %d)", data.TapName, data.ID)
			} else {
				if !strings.Contains(vTapPort.Name, data.TapName) {
					vTapPort.Name = vTapPort.Name + ", " + data.TapName
				} else {
					log.Debugf("duplicate name: %s (id: %d)", data.TapName, data.ID)
				}
			}
			if len(vTapPort.Name) > vTapPortNameLength {
				vTapPort.Name = vTapPort.Name[:vTapPortNameLength]
			}
			if vTapPort.DeviceID == 0 && vTapPort.DeviceType == 0 && data.DeviceID != 0 && data.DeviceType != 0 {
				log.Debugf("device id: %d, device type: %d ", vTapPort.DeviceID, vTapPort.DeviceType)
				vTapPort.DeviceID = data.DeviceID
				vTapPort.DeviceType = data.DeviceType
				vTapPort.DeviceName = data.DeviceName
				vTapPort.IconID = deviceKeyToIconID[DeviceKey{DeviceID: data.DeviceID, DeviceType: data.DeviceType}]
				log.Debugf("device id: %d, device type: %d, device name: %s", data.DeviceID, data.DeviceType, data.DeviceName)
			} else {
				log.Debugf("pass device id: %d, device type: %d, device name: %s", data.DeviceID, data.DeviceType, data.DeviceName)
			}
			vTapPort.TeamID = VTapIDToTeamID[data.VTapID]
			keyToItem[tapMacKey] = vTapPort
			log.Debugf("update: %+v", vTapPort)
		} else {
			if data.VTapID != 0 || tapPort != 0 {
				keyToItem[tapMacKey] = mysql.ChVTapPort{
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
					TeamID:     VTapIDToTeamID[data.VTapID],
				}
				log.Debugf("add new: %+v", keyToItem[tapMacKey])
			}
		}
		// 网卡+MAC
		macKey := VtapPortKey{VtapID: data.VTapID, TapPort: macPort}
		log.Debugf("mac: %s, key: %+v", data.MAC, macKey)
		if tapPort != macPort && macPort != 0 {
			vTapPort, ok := keyToItem[macKey]
			if ok {
				nameSlice := sortVTapPortJoinedNames(&vTapPort)

				if len(nameSlice) >= CH_VTAP_PORT_NAME_MAX {
					if !strings.Contains(vTapPort.Name, ", ...") {
						vTapPort.Name = vTapPort.Name + ", ..."
					}
					log.Debugf("pass name: %s (id: %d)", data.TapName, data.ID)
				} else {
					if !strings.Contains(vTapPort.Name, data.Name) {
						vTapPort.Name = vTapPort.Name + ", " + data.Name
					} else {
						log.Debugf("duplicate name: %s (id: %d)", data.TapName, data.ID)
					}
				}
				if len(vTapPort.Name) > vTapPortNameLength {
					vTapPort.Name = vTapPort.Name[:vTapPortNameLength]
				}
				if vTapPort.DeviceID == 0 && vTapPort.DeviceType == 0 && data.DeviceID != 0 && data.DeviceType != 0 {
					log.Debugf("device id: %d, device type: %d ", vTapPort.DeviceID, vTapPort.DeviceType)
					vTapPort.DeviceID = data.DeviceID
					vTapPort.DeviceType = data.DeviceType
					vTapPort.DeviceName = data.DeviceName
					vTapPort.IconID = deviceKeyToIconID[DeviceKey{DeviceID: data.DeviceID, DeviceType: data.DeviceType}]
					log.Debugf("device id: %d, device type: %d, device name: %s", data.DeviceID, data.DeviceType, data.DeviceName)
				} else {
					log.Debugf("pass device id: %d, device type: %d, device name: %s", data.DeviceID, data.DeviceType, data.DeviceName)
				}
				vTapPort.TeamID = VTapIDToTeamID[data.VTapID]
				keyToItem[macKey] = vTapPort
				log.Debugf("update: %+v", vTapPort)
			} else {
				keyToItem[macKey] = mysql.ChVTapPort{
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
					TeamID:     VTapIDToTeamID[data.VTapID],
				}
				log.Debugf("add new: %+v", keyToItem[tapMacKey])
			}
		}
	}

	vTapIDToDeviceInfo, ok := v.generateVtapDeviceInfo(db)
	if !ok {
		return nil, false
	}
	for vTapID, deviceInfo := range vTapIDToDeviceInfo {
		key := VtapPortKey{VtapID: vTapID, TapPort: 0}
		vTapPort, ok := keyToItem[key]
		if ok {
			nameSlice := sortVTapPortJoinedNames(&vTapPort)

			if len(nameSlice) >= CH_VTAP_PORT_NAME_MAX {
				if !strings.Contains(vTapPort.Name, ", ...") {
					vTapPort.Name = vTapPort.Name + ", ..."
				}
			} else if !common.Contains(nameSlice, "lo") {
				vTapPort.Name = strings.Join([]string{"lo", vTapPort.Name}, ", ")
			}
			if len(vTapPort.Name) > vTapPortNameLength {
				vTapPort.Name = vTapPort.Name[:vTapPortNameLength]
			}
			if vTapPort.DeviceID == 0 && vTapPort.DeviceType == 0 && deviceInfo.DeviceID != 0 && deviceInfo.DeviceType != 0 {
				log.Debugf("device id: %d, device type: %d ", vTapPort.DeviceID, vTapPort.DeviceType)
				vTapPort.DeviceID = deviceInfo.DeviceID
				vTapPort.DeviceType = deviceInfo.DeviceType
				vTapPort.DeviceName = deviceInfo.DeviceName
				vTapPort.IconID = deviceInfo.IconID
				log.Debugf("device id: %d, device type: %d, device name: %s", deviceInfo.DeviceID, deviceInfo.DeviceType, deviceInfo.DeviceName)
			} else {
				log.Debugf("pass device id: %d, device type: %d, device name: %s", deviceInfo.DeviceID, deviceInfo.DeviceType, deviceInfo.DeviceName)
			}
			vTapPort.TeamID = VTapIDToTeamID[vTapID]
		} else if vTapID != 0 {
			keyToItem[key] = mysql.ChVTapPort{
				VTapID:     vTapID,
				TapPort:    0,
				MacType:    0,
				Name:       "lo",
				DeviceID:   deviceInfo.DeviceID,
				DeviceType: deviceInfo.DeviceType,
				DeviceName: deviceInfo.DeviceName,
				IconID:     deviceInfo.IconID,
				TeamID:     VTapIDToTeamID[vTapID],
			}
			log.Debugf("add new: %+v", keyToItem[key])
		}
	}

	for _, host := range hosts {
		for _, vInterface := range vInterfaces {
			if host.ID == vInterface.DeviceID {
				macSlice := strings.Split(vInterface.Mac, ":")
				if len(macSlice) < 3 {
					log.Debugf("invalid vinterface mac: %s", vInterface.Mac)
					continue
				}
				macSlice = macSlice[2:]
				macStr := strings.Join(macSlice, "")
				tapPort, err := strconv.ParseInt(macStr, 16, 64)
				if err != nil {
					log.Errorf("format mac failed: %s, %s, %v", macStr, vInterface.Mac, err)
					continue
				}
				for _, vTap := range vTaps {
					if vTap.ID == 0 && tapPort == 0 {
						continue
					}
					if vTap.Region == "" && vTap.AZ != host.AZ {
						continue
					}
					if vTap.Region != "" && vTap.Region == host.Region {
						key := VtapPortKey{VtapID: vTap.ID, TapPort: tapPort}
						keyToItem[key] = mysql.ChVTapPort{
							VTapID:     vTap.ID,
							TapPort:    tapPort,
							Name:       vInterface.Name + " " + host.Name,
							DeviceID:   host.ID,
							DeviceType: common.VIF_DEVICE_TYPE_HOST,
							DeviceName: host.Name,
							HostID:     host.ID,
							HostName:   host.Name,
							IconID:     deviceKeyToIconID[DeviceKey{DeviceID: host.ID, DeviceType: common.VIF_DEVICE_TYPE_HOST}],
							TeamID:     VTapIDToTeamID[vTap.ID],
						}
						log.Debugf("add new: %+v, %+v", key, keyToItem[key])
					}
				}
			}
		}
	}
	return keyToItem, true
}

func (v *ChVTapPort) generateVtapDeviceInfo(db *mysql.DB) (map[int]DeviceInfo, bool) {
	vTapIDToDeviceInfo := make(map[int]DeviceInfo)

	var hostChDevices []mysql.ChDevice
	err := db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_HOST).Unscoped().Find(&hostChDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return vTapIDToDeviceInfo, false
	}
	var vmChDevices []mysql.ChDevice
	err = db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_VM).Unscoped().Find(&vmChDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return vTapIDToDeviceInfo, false
	}
	var podNodeChDevices []mysql.ChDevice
	err = db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_POD_NODE).Unscoped().Find(&podNodeChDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return vTapIDToDeviceInfo, false
	}
	var podChDevices []mysql.ChDevice
	err = db.Where("devicetype = ?", common.VIF_DEVICE_TYPE_POD).Unscoped().Find(&podChDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return vTapIDToDeviceInfo, false
	}
	var vTaps []mysql.VTap
	err = db.Unscoped().Find(&vTaps).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return vTapIDToDeviceInfo, false
	}

	hostIDToName := make(map[int]string)
	hostIDToIconID := make(map[int]int)
	for _, hostChDevice := range hostChDevices {
		hostIDToName[hostChDevice.DeviceID] = hostChDevice.Name
		hostIDToIconID[hostChDevice.DeviceID] = hostChDevice.IconID
	}
	vmIDToName := make(map[int]string)
	vmIDToIconID := make(map[int]int)
	for _, vmChDevice := range vmChDevices {
		vmIDToName[vmChDevice.DeviceID] = vmChDevice.Name
		vmIDToIconID[vmChDevice.DeviceID] = vmChDevice.IconID
	}
	podNodeIDToName := make(map[int]string)
	podNodeIDToIconID := make(map[int]int)
	for _, podNodeChDevice := range podNodeChDevices {
		podNodeIDToName[podNodeChDevice.DeviceID] = podNodeChDevice.Name
		podNodeIDToIconID[podNodeChDevice.DeviceID] = podNodeChDevice.IconID
	}
	podIDToName := make(map[int]string)
	podIDToIconID := make(map[int]int)
	for _, podChDevice := range podChDevices {
		podIDToName[podChDevice.DeviceID] = podChDevice.Name
		podIDToIconID[podChDevice.DeviceID] = podChDevice.IconID
	}

	for _, vTap := range vTaps {
		if vTap.LaunchServerID == 0 {
			continue
		}
		if vTap.Type == common.VTAP_TYPE_KVM || vTap.Type == common.VTAP_TYPE_ESXI || vTap.Type == common.VTAP_TYPE_HYPER_V {
			vTapIDToDeviceInfo[vTap.ID] = DeviceInfo{
				DeviceType: common.VIF_DEVICE_TYPE_HOST,
				DeviceID:   vTap.LaunchServerID,
				DeviceName: hostIDToName[vTap.LaunchServerID],
				IconID:     hostIDToIconID[vTap.LaunchServerID],
				TeamID:     VTapIDToTeamID[vTap.ID],
			}
		} else if vTap.Type == common.VTAP_TYPE_WORKLOAD_V || vTap.Type == common.VTAP_TYPE_WORKLOAD_P {
			vTapIDToDeviceInfo[vTap.ID] = DeviceInfo{
				DeviceType: common.VIF_DEVICE_TYPE_VM,
				DeviceID:   vTap.LaunchServerID,
				DeviceName: vmIDToName[vTap.LaunchServerID],
				IconID:     vmIDToIconID[vTap.LaunchServerID],
				TeamID:     VTapIDToTeamID[vTap.ID],
			}
		} else if vTap.Type == common.VTAP_TYPE_POD_HOST || vTap.Type == common.VTAP_TYPE_POD_VM {
			vTapIDToDeviceInfo[vTap.ID] = DeviceInfo{
				DeviceType: common.VIF_DEVICE_TYPE_POD_NODE,
				DeviceID:   vTap.LaunchServerID,
				DeviceName: podNodeIDToName[vTap.LaunchServerID],
				IconID:     podNodeIDToIconID[vTap.LaunchServerID],
				TeamID:     VTapIDToTeamID[vTap.ID],
			}
		} else if vTap.Type == common.VTAP_TYPE_K8S_SIDECAR {
			vTapIDToDeviceInfo[vTap.ID] = DeviceInfo{
				DeviceType: common.VIF_DEVICE_TYPE_POD,
				DeviceID:   vTap.LaunchServerID,
				DeviceName: podIDToName[vTap.LaunchServerID],
				IconID:     podIDToIconID[vTap.LaunchServerID],
				TeamID:     VTapIDToTeamID[vTap.ID],
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

// sortVTapPortJoinedNames sorts the joined names of vtap ports, sets sorted name to ChVTapPort and returns the name slice
func sortVTapPortJoinedNames(vtapPort *mysql.ChVTapPort) []string {
	nameSlice := strings.Split(vtapPort.Name, ", ")
	sort.Strings(nameSlice)
	vtapPort.Name = strings.Join(nameSlice, ", ")
	return nameSlice
}

func getVTapInterfaces(orgID int) (resp []model.VTapInterface, err error) {
	return vtap.NewVTapInterface(
		common.FPermit{},
		httpcommon.NewUserInfo(common.USER_TYPE_SUPER_ADMIN, common.USER_ID_SUPER_ADMIN, orgID),
	).Get(map[string]interface{}{})
}
