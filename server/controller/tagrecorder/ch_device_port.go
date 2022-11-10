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
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
)

type ChDevicePort struct {
	UpdaterBase[mysql.ChDevicePort, PortDeviceKey]
}

func NewChDevicePort() *ChDevicePort {
	updater := &ChDevicePort{
		UpdaterBase[mysql.ChDevicePort, PortDeviceKey]{
			resourceTypeName: RESOURCE_TYPE_CH_DEVICE_PORT,
		},
	}
	updater.dataGenerator = updater
	return updater
}

// - 云服务器
//   - 获取负载均衡器和监听器
//     - 查找后端资源为云服务器的负载均衡器和监听器，并匹配协议和端口
// - 负载均衡器
//   - 获取负载均衡器和监听器，并匹配协议和端口
func (d *ChDevicePort) generateNewData() (map[PortDeviceKey]mysql.ChDevicePort, bool) {
	var lbs []mysql.LB
	var lbListeners []mysql.LBListener
	var lbTargetServers []mysql.LBTargetServer
	err := mysql.Db.Unscoped().Find(&lbs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Find(&lbListeners).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Find(&lbTargetServers).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return nil, false
	}

	lbIDToName := make(map[int]string)
	lbListenerIDToName := make(map[int]string)
	for _, lb := range lbs {
		lbIDToName[lb.ID] = lb.Name
	}
	for _, lbListener := range lbListeners {
		lbListenerIDToName[lbListener.ID] = lbListener.Name
	}

	keyToItem := make(map[PortDeviceKey]mysql.ChDevicePort)
	// 云服务器
	for _, lbTargetServer := range lbTargetServers {
		if lbTargetServer.Port == 0 || common.ProtocolMap[lbTargetServer.Protocol] == 0 || lbTargetServer.VMID == 0 {
			continue
		}
		key := PortDeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_VM,
			DeviceID:   lbTargetServer.VMID,
			Protocol:   common.ProtocolMap[lbTargetServer.Protocol],
			Port:       lbTargetServer.Port,
		}
		keyToItem[key] = mysql.ChDevicePort{
			DeviceID:           lbTargetServer.VMID,
			DeviceType:         common.VIF_DEVICE_TYPE_VM,
			Protocol:           common.ProtocolMap[lbTargetServer.Protocol],
			Port:               lbTargetServer.Port,
			PortLBID:           lbTargetServer.LBID,
			PortLBName:         lbIDToName[lbTargetServer.LBID],
			PortLBListenerID:   lbTargetServer.LBListenerID,
			PortLBListenerName: lbListenerIDToName[lbTargetServer.LBListenerID],
		}
	}

	// 负载均衡器
	for _, lbListener := range lbListeners {
		if lbListener.Port == 0 || common.ProtocolMap[lbListener.Protocol] == 0 || lbListener.LBID == 0 {
			continue
		}
		key := PortDeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_LB,
			DeviceID:   lbListener.LBID,
			Protocol:   common.ProtocolMap[lbListener.Protocol],
			Port:       lbListener.Port,
		}
		keyToItem[key] = mysql.ChDevicePort{
			DeviceType:         common.VIF_DEVICE_TYPE_LB,
			DeviceID:           lbListener.LBID,
			Protocol:           common.ProtocolMap[lbListener.Protocol],
			Port:               lbListener.Port,
			PortLBID:           lbListener.LBID,
			PortLBName:         lbIDToName[lbListener.LBID],
			PortLBListenerID:   lbListener.ID,
			PortLBListenerName: lbListener.Name,
		}
	}
	return keyToItem, true
}

func (d *ChDevicePort) generateKey(dbItem mysql.ChDevicePort) PortDeviceKey {
	return PortDeviceKey{DeviceID: dbItem.DeviceID, DeviceType: dbItem.DeviceType, Protocol: dbItem.Protocol, Port: dbItem.Port}
}

func (d *ChDevicePort) generateUpdateInfo(oldItem, newItem mysql.ChDevicePort) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.PortLBID != newItem.PortLBID {
		updateInfo["port_lb_id"] = newItem.PortLBID
	}
	if oldItem.PortLBName != newItem.PortLBName {
		updateInfo["port_lb_name"] = newItem.PortLBName
	}
	if oldItem.PortLBListenerID != newItem.PortLBListenerID {
		updateInfo["port_lb_listener_id"] = newItem.PortLBListenerID
	}
	if oldItem.PortLBListenerName != newItem.PortLBListenerName {
		updateInfo["port_lb_listener_name"] = newItem.PortLBListenerName
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
