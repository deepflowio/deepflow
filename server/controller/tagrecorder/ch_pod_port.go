package tagrecorder

import (
	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

type ChPodPort struct {
	UpdaterBase[mysql.ChPodPort, PortIDKey]
}

func NewChPodPort() *ChPodPort {
	updater := &ChPodPort{
		UpdaterBase[mysql.ChPodPort, PortIDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_PORT,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodPort) generateNewData() (map[PortIDKey]mysql.ChPodPort, bool) {
	var podServices []mysql.PodService
	var pods []mysql.Pod
	var podGroupPorts []mysql.PodGroupPort
	err := mysql.Db.Find(&podServices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Find(&pods).Error
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
	podGroupIDToPodIDs := make(map[int][]int)
	for _, pod := range pods {
		podGroupIDToPodIDs[pod.PodGroupID] = append(podGroupIDToPodIDs[pod.PodGroupID], pod.ID)
	}

	keyToItem := make(map[PortIDKey]mysql.ChPodPort)
	for _, podGroupPort := range podGroupPorts {
		if podGroupPort.Port == 0 || podGroupPort.PodGroupID == 0 || common.ProtocolMap[podGroupPort.Protocol] == 0 {
			continue
		}
		podIDs := podGroupIDToPodIDs[podGroupPort.PodGroupID]
		for _, podID := range podIDs {
			if podID == 0 {
				continue
			}
			key := PortIDKey{
				ID:       podID,
				Protocol: common.ProtocolMap[podGroupPort.Protocol],
				Port:     podGroupPort.Port,
			}
			keyToItem[key] = mysql.ChPodPort{
				ID:                 podID,
				Protocol:           common.ProtocolMap[podGroupPort.Protocol],
				Port:               podGroupPort.Port,
				PortPodServiceID:   podGroupPort.PodServiceID,
				PortPodServiceName: serviceIDToName[podGroupPort.PodServiceID],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodPort) generateKey(dbItem mysql.ChPodPort) PortIDKey {
	return PortIDKey{ID: dbItem.ID, Protocol: dbItem.Protocol, Port: dbItem.Port}
}

func (p *ChPodPort) generateUpdateInfo(oldItem, newItem mysql.ChPodPort) (map[string]interface{}, bool) {
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
