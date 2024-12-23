/*
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

package tagrecorder

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/model"
)

const vTapPortNameLength = 256

type ChVTapPort struct {
	UpdaterBase[metadbmodel.ChVTapPort, VtapPortKey]
}

type DeviceInfo struct {
	DeviceID   int
	DeviceType int
	DeviceName string
	IconID     int
}

func NewChVTapPort() *ChVTapPort {
	updater := &ChVTapPort{
		UpdaterBase[metadbmodel.ChVTapPort, VtapPortKey]{
			resourceTypeName: RESOURCE_TYPE_CH_VTAP_PORT,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (v *ChVTapPort) generateNewData() (map[VtapPortKey]metadbmodel.ChVTapPort, bool) {
	var vTaps []metadbmodel.VTap
	err := metadb.DefaultDB.Where("type = ?", common.VTAP_TYPE_DEDICATED).Unscoped().Find(&vTaps).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err), v.db.LogPrefixORGID)
		return nil, false
	}
	var hosts []metadbmodel.Host
	err = metadb.DefaultDB.Where("htype = ?", common.HOST_HTYPE_GATEWAY).Unscoped().Find(&hosts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err), v.db.LogPrefixORGID)
		return nil, false
	}
	var vInterfaces []metadbmodel.VInterface
	err = metadb.DefaultDB.Where("devicetype = ?", common.VIF_DEVICE_TYPE_HOST).Unscoped().Find(&vInterfaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err), v.db.LogPrefixORGID)
		return nil, false
	}
	var chDevices []metadbmodel.ChDevice
	err = metadb.DefaultDB.Unscoped().Find(&chDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err), v.db.LogPrefixORGID)
		return nil, false
	}
	deviceKeyToIconID := make(map[DeviceKey]int)
	for _, chDevice := range chDevices {
		deviceKeyToIconID[DeviceKey{DeviceID: chDevice.DeviceID, DeviceType: chDevice.DeviceType}] = chDevice.IconID
	}
	vtapVIFs, err := GetVTapInterfaces(nil)
	if err != nil {
		log.Error(errors.New("unable to get resource vtap-port"), v.db.LogPrefixORGID)
		return nil, false
	}
	keyToItem := make(map[VtapPortKey]metadbmodel.ChVTapPort)
	if len(vtapVIFs) == 0 {
		log.Info("no data in get vtap-port response", v.db.LogPrefixORGID)
		return keyToItem, true
	}

	for _, data := range vtapVIFs {
		if data.TapMAC == "" {
			log.Infof("invalid tap mac: %+v", data, v.db.LogPrefixORGID)
			continue
		}
		tapMacSlice := strings.Split(data.TapMAC, ":")
		if len(tapMacSlice) < 3 {
			log.Infof("invalid tap mac: %+v", data, v.db.LogPrefixORGID)
			continue
		}
		tapMacSlice = tapMacSlice[2:]
		tapMacStr := strings.Join(tapMacSlice, "")
		tapPort, err := strconv.ParseInt(tapMacStr, 16, 64)
		if err != nil {
			log.Errorf("format tap mac failed: %s, %+v, %v", tapMacStr, data, err, v.db.LogPrefixORGID)
			continue
		}
		var macPort int64
		if data.MAC == "" {
			log.Infof("no mac: %+v", data, v.db.LogPrefixORGID)
			macPort = 0
		} else {
			macSlice := strings.Split(data.MAC, ":")
			if len(macSlice) < 3 {
				log.Infof("invalid mac %s: %+v", data, v.db.LogPrefixORGID)
				continue
			}
			macSlice = macSlice[2:]
			macStr := strings.Join(macSlice, "")
			macPort, err = strconv.ParseInt(macStr, 16, 64)
			if err != nil {
				log.Errorf("format mac failed: %s, %+v, %v", macStr, data, err, v.db.LogPrefixORGID)
				continue
			}
		}

		// 采集网卡+MAC
		tapMacKey := VtapPortKey{VtapID: data.VTapID, TapPort: tapPort}
		log.Debugf("tap mac: %s, key: %+v", data.TapMAC, tapMacKey, v.db.LogPrefixORGID)
		vTapPort, ok := keyToItem[tapMacKey]
		if ok {
			vTapPort.MacType = CH_VTAP_PORT_TYPE_TAP_MAC
			nameSlice := strings.Split(vTapPort.Name, ", ")
			if len(nameSlice) >= CH_VTAP_PORT_NAME_MAX {
				if !strings.Contains(vTapPort.Name, ", ...") {
					vTapPort.Name = vTapPort.Name + ", ..."
				}
				log.Debugf("pass name: %s (id: %d)", data.TapName, data.ID, v.db.LogPrefixORGID)
			} else {
				if !strings.Contains(vTapPort.Name, data.TapName) {
					vTapPort.Name = vTapPort.Name + ", " + data.TapName
				} else {
					log.Debugf("duplicate name: %s (id: %d)", data.TapName, data.ID, v.db.LogPrefixORGID)
				}
			}
			if len(vTapPort.Name) > vTapPortNameLength {
				vTapPort.Name = vTapPort.Name[:vTapPortNameLength]
			}
			if vTapPort.DeviceID == 0 && vTapPort.DeviceType == 0 && data.DeviceID != 0 && data.DeviceType != 0 {
				log.Debugf("device id: %d, device type: %d ", vTapPort.DeviceID, vTapPort.DeviceType, v.db.LogPrefixORGID)
				vTapPort.DeviceID = data.DeviceID
				vTapPort.DeviceType = data.DeviceType
				vTapPort.DeviceName = data.DeviceName
				vTapPort.IconID = deviceKeyToIconID[DeviceKey{DeviceID: data.DeviceID, DeviceType: data.DeviceType}]
				log.Debugf("device id: %d, device type: %d, device name: %s", data.DeviceID, data.DeviceType, data.DeviceName, v.db.LogPrefixORGID)
			} else {
				log.Debugf("pass device id: %d, device type: %d, device name: %s", data.DeviceID, data.DeviceType, data.DeviceName, v.db.LogPrefixORGID)
			}
			keyToItem[tapMacKey] = vTapPort
			log.Debugf("update: %+v", vTapPort, v.db.LogPrefixORGID)
		} else {
			if data.VTapID != 0 || tapPort != 0 {
				keyToItem[tapMacKey] = metadbmodel.ChVTapPort{
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
				log.Debugf("add new: %+v", keyToItem[tapMacKey], v.db.LogPrefixORGID)
			}
		}
		// 网卡+MAC
		macKey := VtapPortKey{VtapID: data.VTapID, TapPort: macPort}
		log.Debugf("mac: %s, key: %+v", data.MAC, macKey, v.db.LogPrefixORGID)
		if tapPort != macPort && macPort != 0 {
			vTapPort, ok := keyToItem[macKey]
			if ok {
				nameSlice := strings.Split(vTapPort.Name, ", ")
				if len(nameSlice) >= CH_VTAP_PORT_NAME_MAX {
					if !strings.Contains(vTapPort.Name, ", ...") {
						vTapPort.Name = vTapPort.Name + ", ..."
					}
					log.Debugf("pass name: %s (id: %d)", data.TapName, data.ID, v.db.LogPrefixORGID)
				} else {
					if !strings.Contains(vTapPort.Name, data.Name) {
						vTapPort.Name = vTapPort.Name + ", " + data.Name
					} else {
						log.Debugf("duplicate name: %s (id: %d)", data.TapName, data.ID, v.db.LogPrefixORGID)
					}
				}
				if len(vTapPort.Name) > vTapPortNameLength {
					vTapPort.Name = vTapPort.Name[:vTapPortNameLength]
				}
				if vTapPort.DeviceID == 0 && vTapPort.DeviceType == 0 && data.DeviceID != 0 && data.DeviceType != 0 {
					log.Debugf("device id: %d, device type: %d ", vTapPort.DeviceID, vTapPort.DeviceType, v.db.LogPrefixORGID)
					vTapPort.DeviceID = data.DeviceID
					vTapPort.DeviceType = data.DeviceType
					vTapPort.DeviceName = data.DeviceName
					vTapPort.IconID = deviceKeyToIconID[DeviceKey{DeviceID: data.DeviceID, DeviceType: data.DeviceType}]
					log.Debugf("device id: %d, device type: %d, device name: %s", data.DeviceID, data.DeviceType, data.DeviceName, v.db.LogPrefixORGID)
				} else {
					log.Debugf("pass device id: %d, device type: %d, device name: %s", data.DeviceID, data.DeviceType, data.DeviceName, v.db.LogPrefixORGID)
				}
				keyToItem[macKey] = vTapPort
				log.Debugf("update: %+v", vTapPort, v.db.LogPrefixORGID)
			} else {
				keyToItem[macKey] = metadbmodel.ChVTapPort{
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
				log.Debugf("add new: %+v", keyToItem[tapMacKey], v.db.LogPrefixORGID)
			}
		}
	}

	vTapIDToDeviceInfo, ok := v.generateVtapDeviceInfo()
	if !ok {
		return nil, false
	}
	for vTapID, deviceInfo := range vTapIDToDeviceInfo {
		key := VtapPortKey{VtapID: vTapID, TapPort: 0}
		vTapPort, ok := keyToItem[key]
		if ok {
			nameSlice := strings.Split(vTapPort.Name, ", ")
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
				log.Debugf("device id: %d, device type: %d ", vTapPort.DeviceID, vTapPort.DeviceType, v.db.LogPrefixORGID)
				vTapPort.DeviceID = deviceInfo.DeviceID
				vTapPort.DeviceType = deviceInfo.DeviceType
				vTapPort.DeviceName = deviceInfo.DeviceName
				vTapPort.IconID = deviceInfo.IconID
				log.Debugf("device id: %d, device type: %d, device name: %s", deviceInfo.DeviceID, deviceInfo.DeviceType, deviceInfo.DeviceName, v.db.LogPrefixORGID)
			} else {
				log.Debugf("pass device id: %d, device type: %d, device name: %s", deviceInfo.DeviceID, deviceInfo.DeviceType, deviceInfo.DeviceName, v.db.LogPrefixORGID)
			}
		} else if vTapID != 0 {
			keyToItem[key] = metadbmodel.ChVTapPort{
				VTapID:     vTapID,
				TapPort:    0,
				MacType:    0,
				Name:       "lo",
				DeviceID:   deviceInfo.DeviceID,
				DeviceType: deviceInfo.DeviceType,
				DeviceName: deviceInfo.DeviceName,
				IconID:     deviceInfo.IconID,
			}
			log.Debugf("add new: %+v", keyToItem[key], v.db.LogPrefixORGID)
		}
	}

	for _, host := range hosts {
		for _, vInterface := range vInterfaces {
			if host.ID == vInterface.DeviceID {
				macSlice := strings.Split(vInterface.Mac, ":")
				if len(macSlice) < 3 {
					log.Debugf("invalid vinterface mac: %s", vInterface.Mac, v.db.LogPrefixORGID)
					continue
				}
				macSlice = macSlice[2:]
				macStr := strings.Join(macSlice, "")
				tapPort, err := strconv.ParseInt(macStr, 16, 64)
				if err != nil {
					log.Errorf("format mac failed: %s, %s, %v", macStr, vInterface.Mac, err, v.db.LogPrefixORGID)
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
						keyToItem[key] = metadbmodel.ChVTapPort{
							VTapID:     vTap.ID,
							TapPort:    tapPort,
							Name:       vInterface.Name + " " + host.Name,
							DeviceID:   host.ID,
							DeviceType: common.VIF_DEVICE_TYPE_HOST,
							DeviceName: host.Name,
							HostID:     host.ID,
							HostName:   host.Name,
							IconID:     deviceKeyToIconID[DeviceKey{DeviceID: host.ID, DeviceType: common.VIF_DEVICE_TYPE_HOST}],
						}
						log.Debugf("add new: %+v, %+v", key, keyToItem[key], v.db.LogPrefixORGID)
					}
				}
			}
		}
	}
	return keyToItem, true
}

func (v *ChVTapPort) generateVtapDeviceInfo() (map[int]DeviceInfo, bool) {
	vTapIDToDeviceInfo := make(map[int]DeviceInfo)
	var hostChDevices []metadbmodel.ChDevice
	err := metadb.DefaultDB.Where("devicetype = ?", common.VIF_DEVICE_TYPE_HOST).Unscoped().Find(&hostChDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err), v.db.LogPrefixORGID)
		return vTapIDToDeviceInfo, false
	}
	var vmChDevices []metadbmodel.ChDevice
	err = metadb.DefaultDB.Where("devicetype = ?", common.VIF_DEVICE_TYPE_VM).Unscoped().Find(&vmChDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err), v.db.LogPrefixORGID)
		return vTapIDToDeviceInfo, false
	}
	var podNodeChDevices []metadbmodel.ChDevice
	err = metadb.DefaultDB.Where("devicetype = ?", common.VIF_DEVICE_TYPE_POD_NODE).Unscoped().Find(&podNodeChDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err), v.db.LogPrefixORGID)
		return vTapIDToDeviceInfo, false
	}
	var podChDevices []metadbmodel.ChDevice
	err = metadb.DefaultDB.Where("devicetype = ?", common.VIF_DEVICE_TYPE_POD).Unscoped().Find(&podChDevices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err), v.db.LogPrefixORGID)
		return vTapIDToDeviceInfo, false
	}
	var vTaps []metadbmodel.VTap
	err = metadb.DefaultDB.Unscoped().Find(&vTaps).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err), v.db.LogPrefixORGID)
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
		} else if vTap.Type == common.VTAP_TYPE_K8S_SIDECAR {
			vTapIDToDeviceInfo[vTap.ID] = DeviceInfo{
				DeviceType: common.VIF_DEVICE_TYPE_POD,
				DeviceID:   vTap.LaunchServerID,
				DeviceName: podIDToName[vTap.LaunchServerID],
				IconID:     podIDToIconID[vTap.LaunchServerID],
			}
		}
	}
	return vTapIDToDeviceInfo, true
}

func (v *ChVTapPort) generateKey(dbItem metadbmodel.ChVTapPort) VtapPortKey {
	return VtapPortKey{VtapID: dbItem.VTapID, TapPort: dbItem.TapPort}
}

func (v *ChVTapPort) generateUpdateInfo(oldItem, newItem metadbmodel.ChVTapPort) (map[string]interface{}, bool) {
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
	toolDS, err := newToolDataSet()
	if err != nil {
		return nil, err
	}

	controllerIPToRegionLcuuid := make(map[string]string)
	var azCConns []*metadbmodel.AZControllerConnection
	metadb.DefaultDB.Unscoped().Find(&azCConns)
	for _, c := range azCConns {
		controllerIPToRegionLcuuid[c.ControllerIP] = c.Region
	}
	var controllers []*metadbmodel.Controller
	metadb.DefaultDB.Unscoped().Find(&controllers)
	slaveRegionLcuuidToHealthyControllerIPs := make(map[string][]string)
	for _, c := range controllers {
		if c.State == common.CONTROLLER_STATE_NORMAL && c.NodeType == common.CONTROLLER_NODE_TYPE_SLAVE {
			slaveRegionLcuuidToHealthyControllerIPs[controllerIPToRegionLcuuid[c.IP]] = append(
				slaveRegionLcuuidToHealthyControllerIPs[controllerIPToRegionLcuuid[c.IP]], c.IP,
			)
		}
	}

	masterRegionVVIFs := getRawVTapVinterfacesByRegion(common.LOCALHOST, common.GConfig.HTTPPort)
	vtapVIFs = append(vtapVIFs, formatVTapVInterfaces(masterRegionVVIFs, filter, toolDS)...)
	for slaveRegion, regionControllerIPs := range slaveRegionLcuuidToHealthyControllerIPs {
		log.Infof("get region (lcuuid: %s) vtap interfaces", slaveRegion)
		for _, ip := range regionControllerIPs {
			err := common.IsTCPActive(ip, common.GConfig.HTTPNodePort)
			if err != nil {
				log.Error(err.Error())
			} else {
				vtapVIFs = append(vtapVIFs, formatVTapVInterfaces(getRawVTapVinterfacesByRegion(ip, common.GConfig.HTTPNodePort), filter, toolDS)...)
				break
			}
		}
	}
	return vtapVIFs, nil
}

func getRawVTapVinterfacesByRegion(host string, port int) *simplejson.Json {
	url := fmt.Sprintf("http://%s/v1/sync/vinterface/", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	resp, err := common.CURLPerform("GET", url, nil)
	if err != nil {
		log.Errorf("get genesis vinterface failed: %s, %s", err.Error(), url)
		return simplejson.New()
	}
	if len(resp.Get("DATA").MustArray()) == 0 {
		log.Warningf("no data in curl response: %s", url)
		return simplejson.New()
	}
	log.Debug(url)
	return resp.Get("DATA")
}

func formatVTapVInterfaces(vifs *simplejson.Json, filter map[string]interface{}, toolDS *vpToolDataSet) []model.VTapInterface {
	var vtapVIFs []model.VTapInterface
	for i := range vifs.MustArray() {
		jVIF := vifs.GetIndex(i)
		name := jVIF.Get("NAME").MustString()
		if n, ok := filter["name"]; ok {
			if n != name {
				continue
			}
		}
		vtapID := jVIF.Get("VTAP_ID").MustInt()
		lastSeen, err := time.Parse(time.RFC3339, jVIF.Get("LAST_SEEN").MustString())
		if err != nil {
			log.Errorf("parse time (%s) failed: %s", jVIF.Get("LAST_SEEN").MustString(), err.Error())
		}
		vtapVIF := model.VTapInterface{
			ID:       jVIF.Get("ID").MustInt(),
			Name:     name,
			MAC:      jVIF.Get("MAC").MustString(),
			TapName:  jVIF.Get("TAP_NAME").MustString(),
			TapMAC:   jVIF.Get("TAP_MAC").MustString(),
			VTapID:   vtapID,
			HostIP:   jVIF.Get("HOST_IP").MustString(),
			NodeIP:   jVIF.Get("NODE_IP").MustString(),
			LastSeen: lastSeen.Format(common.GO_BIRTHDAY),
		}
		vtap, ok := toolDS.idToVTap[vtapID]
		if ok {
			vtapVIF.VTapLaunchServer = vtap.LaunchServer
			vtapVIF.VTapLaunchServerID = vtap.LaunchServerID
			vtapVIF.VTapType = vtap.Type
			vtapVIF.VTapName = vtap.Name

			macVIFs := toolDS.macToVIFs[vtapVIF.MAC]
			if len(macVIFs) > 0 {
				var macVIF *metadbmodel.VInterface
				if len(macVIFs) == 1 {
					macVIF = macVIFs[0]
				} else {
					// 仅当mac属于host、vm或pod node时，会可能有多个vif，此时需使用与采集器类型匹配的设备类型的vif
					deviceType, ok := VTAP_TYPE_TO_DEVICE_TYPE[vtapVIF.VTapType]
					if ok {
						for _, mv := range macVIFs {
							if mv.DeviceType == deviceType {
								macVIF = mv
								break
							}
						}
					}
					if macVIF == nil {
						log.Warningf("vif with mac: %s not found", vtapVIF.MAC)
						continue
					}
				}
				vtapVIF.DeviceType = macVIF.DeviceType
				vtapVIF.DeviceID = macVIF.DeviceID

				switch vtapVIF.DeviceType {
				case common.VIF_DEVICE_TYPE_HOST:
					vtapVIF.DeviceName = toolDS.hostIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_VM:
					if podNodeID, ok := toolDS.vmIDToPodNodeID[vtapVIF.DeviceID]; ok {
						vtapVIF.DeviceType = common.VIF_DEVICE_TYPE_POD_NODE
						vtapVIF.DeviceID = podNodeID
						vtapVIF.DeviceName = toolDS.podNodeIDToName[podNodeID]
					} else {
						vtapVIF.DeviceName = toolDS.vmIDToName[vtapVIF.DeviceID]
					}
					vtapVIF.DeviceHostID = toolDS.hostIPToID[toolDS.vmIDToLaunchServer[vtapVIF.DeviceID]]
					vtapVIF.DeviceHostName = toolDS.hostIDToName[vtapVIF.DeviceHostID]
				case common.VIF_DEVICE_TYPE_POD_NODE:
					vtapVIF.DeviceName = toolDS.podNodeIDToName[vtapVIF.DeviceID]
					vtapVIF.DeviceHostID = toolDS.hostIPToID[toolDS.vmIDToLaunchServer[toolDS.podNodeIDToVMID[vtapVIF.DeviceID]]]
					vtapVIF.DeviceHostName = toolDS.hostIDToName[vtapVIF.DeviceHostID]
				case common.VIF_DEVICE_TYPE_VROUTER:
					vtapVIF.DeviceName = toolDS.vrouterIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_DHCP_PORT:
					vtapVIF.DeviceName = toolDS.dhcpPortIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_NAT_GATEWAY:
					vtapVIF.DeviceName = toolDS.natGatewayIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_LB:
					vtapVIF.DeviceName = toolDS.lbIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_RDS_INSTANCE:
					vtapVIF.DeviceName = toolDS.rdsInstanceIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_REDIS_INSTANCE:
					vtapVIF.DeviceName = toolDS.redisInstanceIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_POD_SERVICE:
					vtapVIF.DeviceName = toolDS.podServiceIDToName[vtapVIF.DeviceID]
				case common.VIF_DEVICE_TYPE_POD:
					vtapVIF.DeviceName = toolDS.podIDToName[vtapVIF.DeviceID]
				}
			}
		} else if vtapID != 0 {
			log.Errorf("vtap (%d) not found", vtapID)
		}
		vtapVIFs = append(vtapVIFs, vtapVIF)
	}
	return vtapVIFs
}

type vpToolDataSet struct {
	idToVTap              map[int]*metadbmodel.VTap
	macToVIFs             map[string][]*metadbmodel.VInterface
	hostIDToName          map[int]string
	hostIPToID            map[string]int
	vmIDToName            map[int]string
	vmIDToLaunchServer    map[int]string
	podNodeIDToName       map[int]string
	vmIDToPodNodeID       map[int]int
	podNodeIDToVMID       map[int]int
	dhcpPortIDToName      map[int]string
	vrouterIDToName       map[int]string
	natGatewayIDToName    map[int]string
	lbIDToName            map[int]string
	rdsInstanceIDToName   map[int]string
	redisInstanceIDToName map[int]string
	podServiceIDToName    map[int]string
	podIDToName           map[int]string
}

func newToolDataSet() (toolDS *vpToolDataSet, err error) {
	toolDS = &vpToolDataSet{
		idToVTap:              make(map[int]*metadbmodel.VTap),
		macToVIFs:             make(map[string][]*metadbmodel.VInterface),
		hostIDToName:          make(map[int]string),
		hostIPToID:            make(map[string]int),
		vmIDToName:            make(map[int]string),
		vmIDToLaunchServer:    make(map[int]string),
		podNodeIDToName:       make(map[int]string),
		vmIDToPodNodeID:       make(map[int]int),
		podNodeIDToVMID:       make(map[int]int),
		vrouterIDToName:       make(map[int]string),
		dhcpPortIDToName:      make(map[int]string),
		natGatewayIDToName:    make(map[int]string),
		lbIDToName:            make(map[int]string),
		rdsInstanceIDToName:   make(map[int]string),
		redisInstanceIDToName: make(map[int]string),
		podServiceIDToName:    make(map[int]string),
		podIDToName:           make(map[int]string),
	}

	var vtaps []*metadbmodel.VTap
	if err = metadb.DefaultDB.Unscoped().Find(&vtaps).Error; err != nil {
		log.Error(dbQueryResourceFailed("vtap", err))
		return
	}
	for _, vtap := range vtaps {
		toolDS.idToVTap[vtap.ID] = vtap
	}

	var vifs []*metadbmodel.VInterface
	if err = metadb.DefaultDB.Select("mac", "deviceid", "devicetype").Unscoped().Find(&vifs).Error; err != nil {
		log.Error(dbQueryResourceFailed("vinterface", err))
		return
	}
	for _, vif := range vifs {
		toolDS.macToVIFs[vif.Mac] = append(toolDS.macToVIFs[vif.Mac], vif)
	}

	var hosts []*metadbmodel.Host
	if err = metadb.DefaultDB.Select("id", "name").Unscoped().Find(&hosts).Error; err != nil {
		log.Error(dbQueryResourceFailed("host_device", err))
		return
	}
	for _, host := range hosts {
		toolDS.hostIDToName[host.ID] = host.Name
	}

	var vms []*metadbmodel.VM
	if err = metadb.DefaultDB.Select("id", "name", "launch_server").Unscoped().Find(&vms).Error; err != nil {
		log.Error(dbQueryResourceFailed("vm", err))
		return
	}
	for _, vm := range vms {
		toolDS.vmIDToName[vm.ID] = vm.Name
		toolDS.vmIDToLaunchServer[vm.ID] = vm.LaunchServer
	}

	var podNodes []*metadbmodel.PodNode
	if err = metadb.DefaultDB.Select("id", "name").Unscoped().Find(&podNodes).Error; err != nil {
		log.Error(dbQueryResourceFailed("pod_node", err))
		return
	}
	for _, podNode := range podNodes {
		toolDS.podNodeIDToName[podNode.ID] = podNode.Name
	}

	var vmPodNodeConns []*metadbmodel.VMPodNodeConnection
	if err = metadb.DefaultDB.Unscoped().Find(&vmPodNodeConns).Error; err != nil {
		log.Error(dbQueryResourceFailed("vm_pod_node_connection", err))
		return
	}
	for _, conn := range vmPodNodeConns {
		toolDS.vmIDToPodNodeID[conn.VMID] = conn.PodNodeID
		toolDS.podNodeIDToVMID[conn.PodNodeID] = conn.VMID
	}

	var vrouters []*metadbmodel.VRouter
	if err = metadb.DefaultDB.Select("id", "name").Unscoped().Find(&vrouters).Error; err != nil {
		log.Error(dbQueryResourceFailed("vrouter", err))
		return
	}
	for _, v := range vrouters {
		toolDS.vrouterIDToName[v.ID] = v.Name
	}

	var dhcpPorts []*metadbmodel.DHCPPort
	if err = metadb.DefaultDB.Select("id", "name").Unscoped().Find(&dhcpPorts).Error; err != nil {
		log.Error(dbQueryResourceFailed("dhcp_port", err))
		return
	}
	for _, d := range dhcpPorts {
		toolDS.dhcpPortIDToName[d.ID] = d.Name
	}

	var ngws []*metadbmodel.NATGateway
	if err = metadb.DefaultDB.Select("id", "name").Unscoped().Find(&ngws).Error; err != nil {
		log.Error(dbQueryResourceFailed("nat_gateway", err))
		return
	}
	for _, n := range ngws {
		toolDS.natGatewayIDToName[n.ID] = n.Name
	}

	var lbs []*metadbmodel.LB
	if err = metadb.DefaultDB.Select("id", "name").Unscoped().Find(&lbs).Error; err != nil {
		log.Error(dbQueryResourceFailed("lb", err))
		return
	}
	for _, lb := range lbs {
		toolDS.lbIDToName[lb.ID] = lb.Name
	}

	var rdsInstances []*metadbmodel.RDSInstance
	if err = metadb.DefaultDB.Select("id", "name").Unscoped().Find(&rdsInstances).Error; err != nil {
		log.Error(dbQueryResourceFailed("rds_instance", err))
		return
	}
	for _, r := range rdsInstances {
		toolDS.rdsInstanceIDToName[r.ID] = r.Name
	}

	var redisInstances []*metadbmodel.RedisInstance
	if err = metadb.DefaultDB.Select("id", "name").Unscoped().Find(&redisInstances).Error; err != nil {
		log.Error(dbQueryResourceFailed("redis_instance", err))
		return
	}
	for _, r := range redisInstances {
		toolDS.redisInstanceIDToName[r.ID] = r.Name
	}

	var podServices []*metadbmodel.PodService
	if err = metadb.DefaultDB.Select("id", "name").Unscoped().Find(&podServices).Error; err != nil {
		log.Error(dbQueryResourceFailed("pod_service", err))
		return
	}
	for _, p := range podServices {
		toolDS.podServiceIDToName[p.ID] = p.Name
	}

	var pods []*metadbmodel.Pod
	if err = metadb.DefaultDB.Select("id", "name").Unscoped().Find(&pods).Error; err != nil {
		log.Error(dbQueryResourceFailed("pod", err))
		return
	}
	for _, p := range pods {
		toolDS.podIDToName[p.ID] = p.Name
	}
	return
}
