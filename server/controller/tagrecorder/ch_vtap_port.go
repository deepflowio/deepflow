package tagrecorder

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"server/controller/common"
	"server/controller/db/mysql"
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
	body := make(map[string]interface{})
	response, err := common.CURLPerform("GET", "http://talker:20013/v2/vtap-interfaces/", body)
	if err != nil {
		log.Error(errors.New("unable to get resource vtap-port"))
		return nil, false
	}
	keyToItem := make(map[VtapPortKey]mysql.ChVTapPort)
	if len(response.Get("DATA").MustArray()) == 0 {
		log.Error(errors.New("no data in get vtap-port response"))
		return keyToItem, true
	}

	for i, _ := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		if data.Get("TAP_MAC").MustString() == "" {
			continue
		}
		tapMacSlice := strings.Split(data.Get("TAP_MAC").MustString(), ":")
		tapMacSlice = tapMacSlice[2:]
		tapMacStr := strings.Join(tapMacSlice, "")
		tapPort, err := strconv.ParseInt(tapMacStr, 16, 64)
		if err != nil {
			log.Error(err)
			return nil, false
		}
		var macPort int64
		if data.Get("MAC").MustString() == "" {
			macPort = 0
		} else {
			macSlice := strings.Split(data.Get("MAC").MustString(), ":")
			macSlice = macSlice[2:]
			macStr := strings.Join(macSlice, "")
			macPort, err = strconv.ParseInt(macStr, 16, 64)
			if err != nil {
				log.Error(err)
				return nil, false
			}
		}
		// 采集网卡+MAC
		vTapPort, ok := keyToItem[VtapPortKey{VtapID: data.Get("VTAP_ID").MustInt(), TapPort: tapPort}]
		if ok {
			vTapPort.MacType = CH_VTAP_PORT_TYPE_TAP_MAC
			nameSlice := strings.Split(vTapPort.Name, ", ")
			if len(nameSlice) >= CH_VTAP_PORT_NAME_MAX {
				if !strings.Contains(vTapPort.Name, ", ...") {
					vTapPort.Name = vTapPort.Name + ", ..."
				}
			} else {
				if !strings.Contains(vTapPort.Name, data.Get("TAP_NAME").MustString()) {
					vTapPort.Name = vTapPort.Name + ", " + data.Get("TAP_NAME").MustString()
				}
			}
			if vTapPort.DeviceID == 0 && vTapPort.DeviceType == 0 && data.Get("DEVICE_ID").MustInt() != 0 && data.Get("DEVICE_TYPE").MustInt() != 0 {
				vTapPort.DeviceID = data.Get("DEVICE_ID").MustInt()
				vTapPort.DeviceType = data.Get("DEVICE_TYPE").MustInt()
				vTapPort.DeviceName = data.Get("DEVICE_NAME").MustString()
				vTapPort.IconID = deviceKeyToIconID[DeviceKey{DeviceID: data.Get("DEVICE_ID").MustInt(), DeviceType: data.Get("DEVICE_TYPE").MustInt()}]
			}
		} else {
			keyToItem[VtapPortKey{VtapID: data.Get("VTAP_ID").MustInt(), TapPort: tapPort}] = mysql.ChVTapPort{
				VTapID:     data.Get("VTAP_ID").MustInt(),
				TapPort:    tapPort,
				MacType:    CH_VTAP_PORT_TYPE_TAP_MAC,
				Name:       data.Get("TAP_NAME").MustString(),
				DeviceID:   data.Get("DEVICE_ID").MustInt(),
				HostID:     data.Get("DEVICE_HOST_ID").MustInt(),
				DeviceType: data.Get("DEVICE_TYPE").MustInt(),
				DeviceName: data.Get("DEVICE_NAME").MustString(),
				HostName:   data.Get("DEVICE_HOST_NAME").MustString(),
				IconID:     deviceKeyToIconID[DeviceKey{DeviceID: data.Get("DEVICE_ID").MustInt(), DeviceType: data.Get("DEVICE_TYPE").MustInt()}],
			}
		}
		// 网卡+MAC
		if tapPort != macPort && macPort != 0 {
			vTapPort, ok := keyToItem[VtapPortKey{VtapID: data.Get("VTAP_ID").MustInt(), TapPort: macPort}]
			if ok {
				nameSlice := strings.Split(vTapPort.Name, ", ")
				if len(nameSlice) >= CH_VTAP_PORT_NAME_MAX {
					if !strings.Contains(vTapPort.Name, ", ...") {
						vTapPort.Name = vTapPort.Name + ", ..."
					}
				} else {
					if !strings.Contains(vTapPort.Name, data.Get("NAME").MustString()) {
						vTapPort.Name = vTapPort.Name + ", " + data.Get("NAME").MustString()
					}
				}
				if vTapPort.DeviceID == 0 && vTapPort.DeviceType == 0 && data.Get("DEVICE_ID").MustInt() != 0 && data.Get("DEVICE_TYPE").MustInt() != 0 {
					vTapPort.DeviceID = data.Get("DEVICE_ID").MustInt()
					vTapPort.DeviceType = data.Get("DEVICE_TYPE").MustInt()
					vTapPort.DeviceName = data.Get("DEVICE_NAME").MustString()
					vTapPort.IconID = deviceKeyToIconID[DeviceKey{DeviceID: data.Get("DEVICE_ID").MustInt(), DeviceType: data.Get("DEVICE_TYPE").MustInt()}]
				}
			} else {
				keyToItem[VtapPortKey{VtapID: data.Get("VTAP_ID").MustInt(), TapPort: macPort}] = mysql.ChVTapPort{
					VTapID:     data.Get("VTAP_ID").MustInt(),
					TapPort:    macPort,
					MacType:    CH_VTAP_PORT_TYPE_TAP_MAC,
					Name:       data.Get("NAME").MustString(),
					DeviceID:   data.Get("DEVICE_ID").MustInt(),
					HostID:     data.Get("DEVICE_HOST_ID").MustInt(),
					DeviceType: data.Get("DEVICE_TYPE").MustInt(),
					DeviceName: data.Get("DEVICE_NAME").MustString(),
					HostName:   data.Get("DEVICE_HOST_NAME").MustString(),
					IconID:     deviceKeyToIconID[DeviceKey{DeviceID: data.Get("DEVICE_ID").MustInt(), DeviceType: data.Get("DEVICE_TYPE").MustInt()}],
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
