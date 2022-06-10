package tagrecorder

import (
	"server/controller/common"
	"server/controller/db/mysql"
)

type ChPodGroupPort struct {
	UpdaterBase[mysql.ChPodGroupPort, PortIDKey]
}

func NewChPodGroupPort() *ChPodGroupPort {
	updater := &ChPodGroupPort{
		UpdaterBase[mysql.ChPodGroupPort, PortIDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_GROUP_PORT,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodGroupPort) generateNewData() (map[PortIDKey]mysql.ChPodGroupPort, bool) {
	var podServices []mysql.PodService
	var podGroupPorts []mysql.PodGroupPort
	err := mysql.Db.Find(&podServices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Find(&podGroupPorts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	serviceIDToName := make(map[int]string)
	for _, podService := range podServices {
		serviceIDToName[podService.ID] = podService.Name
	}

	keyToItem := make(map[PortIDKey]mysql.ChPodGroupPort)
	for _, podGroupPort := range podGroupPorts {
		if podGroupPort.Port == 0 || podGroupPort.PodGroupID == 0 || common.ProtocolMap[podGroupPort.Protocol] == 0 {
			continue
		}
		key := PortIDKey{
			ID:       podGroupPort.PodGroupID,
			Protocol: common.ProtocolMap[podGroupPort.Protocol],
			Port:     podGroupPort.Port,
		}
		keyToItem[key] = mysql.ChPodGroupPort{
			ID:                 podGroupPort.PodGroupID,
			Protocol:           common.ProtocolMap[podGroupPort.Protocol],
			Port:               podGroupPort.Port,
			PortPodServiceID:   podGroupPort.PodServiceID,
			PortPodServiceName: serviceIDToName[podGroupPort.PodServiceID],
		}
	}
	return keyToItem, true
}

func (p *ChPodGroupPort) generateKey(dbItem mysql.ChPodGroupPort) PortIDKey {
	return PortIDKey{ID: dbItem.ID, Protocol: dbItem.Protocol, Port: dbItem.Port}
}

func (p *ChPodGroupPort) generateUpdateInfo(oldItem, newItem mysql.ChPodGroupPort) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.PortPodServiceID != newItem.PortPodServiceID {
		updateInfo["port_pod_service_id"] = newItem.PortPodServiceID
	}
	if oldItem.PortPodServiceName != newItem.PortPodServiceName {
		updateInfo["port_pod_service_name"] = newItem.PortPodServiceName
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
