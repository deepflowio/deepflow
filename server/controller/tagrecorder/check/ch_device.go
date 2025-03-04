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
	"github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/query"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChDevice struct {
	UpdaterBase[metadbmodel.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChDevice(resourceTypeToIconID map[IconKey]int) *ChDevice {
	updater := &ChDevice{
		UpdaterBase[metadbmodel.ChDevice, DeviceKey]{
			resourceTypeName: RESOURCE_TYPE_CH_DEVICE,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (d *ChDevice) generateNewData() (map[DeviceKey]metadbmodel.ChDevice, bool) {
	log.Infof("generate data for %s", d.resourceTypeName, d.db.LogPrefixORGID)
	keyToItem := make(map[DeviceKey]metadbmodel.ChDevice)
	ok := d.generateHostData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generateVMData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generateVRouterData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generateDHCPPortData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generateNATGatewayData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generateLBData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generateRDSInstanceData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generateRedisInstanceData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generatePodServiceData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generatePodData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generatePodGroupData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generatePodNodeData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generatePodClusterData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generateProcessData(keyToItem)
	if !ok {
		return nil, false
	}
	ok = d.generateCustomServiceData(keyToItem)
	if !ok {
		return nil, false
	}
	d.generateIPData(keyToItem)
	d.generateInternetData(keyToItem)
	return keyToItem, true
}

func (d *ChDevice) generateKey(dbItem metadbmodel.ChDevice) DeviceKey {
	return DeviceKey{
		DeviceType: dbItem.DeviceType,
		DeviceID:   dbItem.DeviceID,
	}
}

func (d *ChDevice) generateUpdateInfo(oldItem, newItem metadbmodel.ChDevice) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID && newItem.IconID != 0 {
		updateInfo["icon_id"] = newItem.IconID
	}
	if oldItem.UID != newItem.UID {
		updateInfo["uid"] = newItem.UID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (d *ChDevice) generateHostData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var hosts []metadbmodel.Host
	err := d.db.Unscoped().Find(&hosts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, host := range hosts {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_HOST,
			DeviceID:   host.ID,
		}
		if host.DeletedAt.Valid {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_HOST,
				DeviceID:   host.ID,
				Name:       host.Name + " (deleted)",
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_HOST, SubType: host.HType}],
				Hostname:   host.Hostname,
				IP:         host.IP,
				TeamID:     tagrecorder.DomainToTeamID[host.Domain],
				DomainID:   tagrecorder.DomainToDomainID[host.Domain],
			}
		} else {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_HOST,
				DeviceID:   host.ID,
				Name:       host.Name,
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_HOST, SubType: host.HType}],
				Hostname:   host.Hostname,
				IP:         host.IP,
				TeamID:     tagrecorder.DomainToTeamID[host.Domain],
				DomainID:   tagrecorder.DomainToDomainID[host.Domain],
			}
		}

	}
	return true
}

func (d *ChDevice) generateVMData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var vms []metadbmodel.VM
	err := d.db.Unscoped().Find(&vms).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, vm := range vms {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_VM,
			DeviceID:   vm.ID,
		}

		if vm.DeletedAt.Valid {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_VM,
				DeviceID:   vm.ID,
				Name:       vm.Name + " (deleted)",
				UID:        vm.UID,
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VM, SubType: vm.HType}],
				Hostname:   vm.Hostname,
				IP:         vm.IP,
				TeamID:     tagrecorder.DomainToTeamID[vm.Domain],
				DomainID:   tagrecorder.DomainToDomainID[vm.Domain],
			}
		} else {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_VM,
				DeviceID:   vm.ID,
				Name:       vm.Name,
				UID:        vm.UID,
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VM, SubType: vm.HType}],
				Hostname:   vm.Hostname,
				IP:         vm.IP,
				TeamID:     tagrecorder.DomainToTeamID[vm.Domain],
				DomainID:   tagrecorder.DomainToDomainID[vm.Domain],
			}
		}
	}
	return true
}

func (d *ChDevice) generateVRouterData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var vrouters []metadbmodel.VRouter
	err := d.db.Unscoped().Find(&vrouters).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, vrouter := range vrouters {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_VROUTER,
			DeviceID:   vrouter.ID,
		}
		vrouterName := vrouter.Name
		if vrouter.DeletedAt.Valid {
			vrouterName += " (deleted)"
		}
		keyToItem[key] = metadbmodel.ChDevice{
			DeviceType: common.VIF_DEVICE_TYPE_VROUTER,
			DeviceID:   vrouter.ID,
			Name:       vrouterName,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VGW}],
			TeamID:     tagrecorder.DomainToTeamID[vrouter.Domain],
			DomainID:   tagrecorder.DomainToDomainID[vrouter.Domain],
		}
	}
	return true
}

func (d *ChDevice) generateDHCPPortData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var dhcpPorts []metadbmodel.DHCPPort
	err := d.db.Unscoped().Find(&dhcpPorts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, dhcpPort := range dhcpPorts {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_DHCP_PORT,
			DeviceID:   dhcpPort.ID,
		}

		if dhcpPort.DeletedAt.Valid {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_DHCP_PORT,
				DeviceID:   dhcpPort.ID,
				Name:       dhcpPort.Name + " (deleted)",
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_DHCP_PORT}],
				TeamID:     tagrecorder.DomainToTeamID[dhcpPort.Domain],
				DomainID:   tagrecorder.DomainToDomainID[dhcpPort.Domain],
			}
		} else {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_DHCP_PORT,
				DeviceID:   dhcpPort.ID,
				Name:       dhcpPort.Name,
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_DHCP_PORT}],
				TeamID:     tagrecorder.DomainToTeamID[dhcpPort.Domain],
				DomainID:   tagrecorder.DomainToDomainID[dhcpPort.Domain],
			}
		}
	}
	return true
}

func (d *ChDevice) generateNATGatewayData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var natGateways []metadbmodel.NATGateway
	err := d.db.Unscoped().Find(&natGateways).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, natGateway := range natGateways {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_NAT_GATEWAY,
			DeviceID:   natGateway.ID,
		}

		if natGateway.DeletedAt.Valid {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_NAT_GATEWAY,
				DeviceID:   natGateway.ID,
				Name:       natGateway.Name + " (deleted)",
				UID:        natGateway.UID,
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_NAT_GATEWAY}],
				TeamID:     tagrecorder.DomainToTeamID[natGateway.Domain],
				DomainID:   tagrecorder.DomainToDomainID[natGateway.Domain],
			}
		} else {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_NAT_GATEWAY,
				DeviceID:   natGateway.ID,
				Name:       natGateway.Name,
				UID:        natGateway.UID,
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_NAT_GATEWAY}],
				TeamID:     tagrecorder.DomainToTeamID[natGateway.Domain],
				DomainID:   tagrecorder.DomainToDomainID[natGateway.Domain],
			}
		}
	}
	return true
}

func (d *ChDevice) generateLBData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var lbs []metadbmodel.LB
	err := d.db.Unscoped().Find(&lbs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, lb := range lbs {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_LB,
			DeviceID:   lb.ID,
		}

		if lb.DeletedAt.Valid {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_LB,
				DeviceID:   lb.ID,
				Name:       lb.Name + " (deleted)",
				UID:        lb.UID,
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_LB}],
				TeamID:     tagrecorder.DomainToTeamID[lb.Domain],
				DomainID:   tagrecorder.DomainToDomainID[lb.Domain],
			}
		} else {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_LB,
				DeviceID:   lb.ID,
				Name:       lb.Name,
				UID:        lb.UID,
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_LB}],
				TeamID:     tagrecorder.DomainToTeamID[lb.Domain],
				DomainID:   tagrecorder.DomainToDomainID[lb.Domain],
			}
		}
	}
	return true
}

func (d *ChDevice) generateRDSInstanceData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var rdsInstances []metadbmodel.RDSInstance
	err := d.db.Unscoped().Find(&rdsInstances).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, rdsInstance := range rdsInstances {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_RDS_INSTANCE,
			DeviceID:   rdsInstance.ID,
		}

		if rdsInstance.DeletedAt.Valid {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_RDS_INSTANCE,
				DeviceID:   rdsInstance.ID,
				Name:       rdsInstance.Name + " (deleted)",
				UID:        rdsInstance.UID,
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_RDS}],
				TeamID:     tagrecorder.DomainToTeamID[rdsInstance.Domain],
				DomainID:   tagrecorder.DomainToDomainID[rdsInstance.Domain],
			}
		} else {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_RDS_INSTANCE,
				DeviceID:   rdsInstance.ID,
				Name:       rdsInstance.Name,
				UID:        rdsInstance.UID,
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_RDS}],
				TeamID:     tagrecorder.DomainToTeamID[rdsInstance.Domain],
				DomainID:   tagrecorder.DomainToDomainID[rdsInstance.Domain],
			}
		}
	}
	return true
}

func (d *ChDevice) generateRedisInstanceData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var redisInstances []metadbmodel.RedisInstance
	err := d.db.Unscoped().Find(&redisInstances).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, redisInstance := range redisInstances {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
			DeviceID:   redisInstance.ID,
		}

		if redisInstance.DeletedAt.Valid {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
				DeviceID:   redisInstance.ID,
				Name:       redisInstance.Name + " (deleted)",
				UID:        redisInstance.UID,
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_REDIS}],
				TeamID:     tagrecorder.DomainToTeamID[redisInstance.Domain],
				DomainID:   tagrecorder.DomainToDomainID[redisInstance.Domain],
			}
		} else {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType: common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
				DeviceID:   redisInstance.ID,
				Name:       redisInstance.Name,
				UID:        redisInstance.UID,
				IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_REDIS}],
				TeamID:     tagrecorder.DomainToTeamID[redisInstance.Domain],
				DomainID:   tagrecorder.DomainToDomainID[redisInstance.Domain],
			}
		}
	}
	return true
}

func (d *ChDevice) generatePodServiceData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var podServices []metadbmodel.PodService
	err := d.db.Unscoped().Find(&podServices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, podService := range podServices {
		teamID, err := tagrecorder.GetTeamID(podService.Domain, podService.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", d.resourceTypeName, err.Error(), podService, d.db.LogPrefixORGID)
		}
		if podService.DeletedAt.Valid {
			podServiceKey := DeviceKey{
				DeviceType: common.VIF_DEVICE_TYPE_POD_SERVICE,
				DeviceID:   podService.ID,
			}
			keyToItem[podServiceKey] = metadbmodel.ChDevice{
				DeviceType:  common.VIF_DEVICE_TYPE_POD_SERVICE,
				DeviceID:    podService.ID,
				Name:        podService.Name + " (deleted)",
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_SERVICE}],
				TeamID:      teamID,
				DomainID:    tagrecorder.DomainToDomainID[podService.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podService.SubDomain],
			}

			// service
			serviceKey := DeviceKey{
				DeviceType: CH_DEVICE_TYPE_SERVICE,
				DeviceID:   podService.ID,
			}
			keyToItem[serviceKey] = metadbmodel.ChDevice{
				DeviceType:  CH_DEVICE_TYPE_SERVICE,
				DeviceID:    podService.ID,
				Name:        podService.Name + " (deleted)",
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_SERVICE}],
				TeamID:      teamID,
				DomainID:    tagrecorder.DomainToDomainID[podService.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podService.SubDomain],
			}
		} else {
			// pod_service
			podServiceKey := DeviceKey{
				DeviceType: common.VIF_DEVICE_TYPE_POD_SERVICE,
				DeviceID:   podService.ID,
			}
			keyToItem[podServiceKey] = metadbmodel.ChDevice{
				DeviceType:  common.VIF_DEVICE_TYPE_POD_SERVICE,
				DeviceID:    podService.ID,
				Name:        podService.Name,
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_SERVICE}],
				TeamID:      tagrecorder.DomainToTeamID[podService.Domain],
				DomainID:    tagrecorder.DomainToDomainID[podService.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podService.SubDomain],
			}

			// service
			serviceKey := DeviceKey{
				DeviceType: CH_DEVICE_TYPE_SERVICE,
				DeviceID:   podService.ID,
			}
			keyToItem[serviceKey] = metadbmodel.ChDevice{
				DeviceType:  CH_DEVICE_TYPE_SERVICE,
				DeviceID:    podService.ID,
				Name:        podService.Name,
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_SERVICE}],
				TeamID:      tagrecorder.DomainToTeamID[podService.Domain],
				DomainID:    tagrecorder.DomainToDomainID[podService.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podService.SubDomain],
			}
		}
	}
	return true
}

func (d *ChDevice) generatePodData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var pods []metadbmodel.Pod
	err := d.db.Unscoped().Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, pod := range pods {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_POD,
			DeviceID:   pod.ID,
		}
		if pod.DeletedAt.Valid {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType:  common.VIF_DEVICE_TYPE_POD,
				DeviceID:    pod.ID,
				Name:        pod.Name + " (deleted)",
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD}],
				TeamID:      tagrecorder.DomainToTeamID[pod.Domain],
				DomainID:    tagrecorder.DomainToDomainID[pod.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[pod.SubDomain],
			}
		} else {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType:  common.VIF_DEVICE_TYPE_POD,
				DeviceID:    pod.ID,
				Name:        pod.Name,
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD}],
				TeamID:      tagrecorder.DomainToTeamID[pod.Domain],
				DomainID:    tagrecorder.DomainToDomainID[pod.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[pod.SubDomain],
			}
		}
	}
	return true
}

func (d *ChDevice) generatePodGroupData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var podGroups []metadbmodel.PodGroup
	err := d.db.Unscoped().Find(&podGroups).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, podGroup := range podGroups {
		key := DeviceKey{
			DeviceType: RESOURCE_POD_GROUP_TYPE_MAP[podGroup.Type],
			DeviceID:   podGroup.ID,
		}
		if podGroup.DeletedAt.Valid {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType:  RESOURCE_POD_GROUP_TYPE_MAP[podGroup.Type],
				DeviceID:    podGroup.ID,
				Name:        podGroup.Name + " (deleted)",
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_GROUP}],
				TeamID:      tagrecorder.DomainToTeamID[podGroup.Domain],
				DomainID:    tagrecorder.DomainToDomainID[podGroup.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podGroup.SubDomain],
			}
		} else {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType:  RESOURCE_POD_GROUP_TYPE_MAP[podGroup.Type],
				DeviceID:    podGroup.ID,
				Name:        podGroup.Name,
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_GROUP}],
				TeamID:      tagrecorder.DomainToTeamID[podGroup.Domain],
				DomainID:    tagrecorder.DomainToDomainID[podGroup.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podGroup.SubDomain],
			}
		}
	}
	return true
}

func (d *ChDevice) generatePodNodeData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var podNodes []metadbmodel.PodNode
	err := d.db.Unscoped().Find(&podNodes).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, podNode := range podNodes {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_POD_NODE,
			DeviceID:   podNode.ID,
		}
		if podNode.DeletedAt.Valid {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType:  common.VIF_DEVICE_TYPE_POD_NODE,
				DeviceID:    podNode.ID,
				Name:        podNode.Name + " (deleted)",
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NODE}],
				Hostname:    podNode.Hostname,
				IP:          podNode.IP,
				TeamID:      tagrecorder.DomainToTeamID[podNode.Domain],
				DomainID:    tagrecorder.DomainToDomainID[podNode.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podNode.SubDomain],
			}
		} else {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType:  common.VIF_DEVICE_TYPE_POD_NODE,
				DeviceID:    podNode.ID,
				Name:        podNode.Name,
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NODE}],
				Hostname:    podNode.Hostname,
				IP:          podNode.IP,
				TeamID:      tagrecorder.DomainToTeamID[podNode.Domain],
				DomainID:    tagrecorder.DomainToDomainID[podNode.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podNode.SubDomain],
			}
		}
	}
	return true
}

func (d *ChDevice) generatePodClusterData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	var podClusters []metadbmodel.PodCluster
	err := d.db.Unscoped().Find(&podClusters).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}

	for _, podCluster := range podClusters {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_POD_CLUSTER,
			DeviceID:   podCluster.ID,
		}
		if podCluster.DeletedAt.Valid {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType:  common.VIF_DEVICE_TYPE_POD_CLUSTER,
				DeviceID:    podCluster.ID,
				Name:        podCluster.Name + " (deleted)",
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_CLUSTER}],
				TeamID:      tagrecorder.DomainToTeamID[podCluster.Domain],
				DomainID:    tagrecorder.DomainToDomainID[podCluster.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podCluster.SubDomain],
			}
		} else {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType:  common.VIF_DEVICE_TYPE_POD_CLUSTER,
				DeviceID:    podCluster.ID,
				Name:        podCluster.Name,
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_CLUSTER}],
				TeamID:      tagrecorder.DomainToTeamID[podCluster.Domain],
				DomainID:    tagrecorder.DomainToDomainID[podCluster.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podCluster.SubDomain],
			}
		}
	}
	return true
}

func (d *ChDevice) generateIPData(keyToItem map[DeviceKey]metadbmodel.ChDevice) {
	key := DeviceKey{
		DeviceType: CH_DEVICE_TYPE_IP,
		DeviceID:   CH_DEVICE_TYPE_IP,
	}
	keyToItem[key] = metadbmodel.ChDevice{
		DeviceType: CH_DEVICE_TYPE_IP,
		DeviceID:   CH_DEVICE_TYPE_IP,
		IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_IP}],
	}
}

func (d *ChDevice) generateInternetData(keyToItem map[DeviceKey]metadbmodel.ChDevice) {
	key := DeviceKey{
		DeviceType: CH_DEVICE_TYPE_INTERNET,
		DeviceID:   CH_DEVICE_TYPE_INTERNET,
	}
	keyToItem[key] = metadbmodel.ChDevice{
		DeviceType: CH_DEVICE_TYPE_INTERNET,
		DeviceID:   CH_DEVICE_TYPE_INTERNET,
		Name:       "Internet",
		IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_INTERNET}],
	}
}

func (d *ChDevice) generateProcessData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	processes, err := query.FindInBatches[metadbmodel.Process](d.db.Unscoped())
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}
	for _, process := range processes {
		key := DeviceKey{
			DeviceType: CH_DEVICE_TYPE_GPROCESS,
			DeviceID:   process.ID,
		}
		if process.DeletedAt.Valid {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType:  CH_DEVICE_TYPE_GPROCESS,
				DeviceID:    process.ID,
				Name:        process.Name + " (deleted)",
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_GPROCESS}],
				TeamID:      tagrecorder.DomainToTeamID[process.Domain],
				DomainID:    tagrecorder.DomainToDomainID[process.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[process.SubDomain],
			}
		} else {
			keyToItem[key] = metadbmodel.ChDevice{
				DeviceType:  CH_DEVICE_TYPE_GPROCESS,
				DeviceID:    process.ID,
				Name:        process.Name,
				IconID:      d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_GPROCESS}],
				TeamID:      tagrecorder.DomainToTeamID[process.Domain],
				DomainID:    tagrecorder.DomainToDomainID[process.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[process.SubDomain],
			}
		}
	}
	return true
}

func (d *ChDevice) generateCustomServiceData(keyToItem map[DeviceKey]metadbmodel.ChDevice) bool {
	customServices, err := query.FindInBatches[metadbmodel.CustomService](d.db.Unscoped())
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err), d.db.LogPrefixORGID)
		return false
	}
	for _, customService := range customServices {
		key := DeviceKey{
			DeviceType: CH_DEVICE_TYPE_CUSTOM_SERVICE,
			DeviceID:   customService.ID,
		}
		keyToItem[key] = metadbmodel.ChDevice{
			DeviceType: CH_DEVICE_TYPE_CUSTOM_SERVICE,
			DeviceID:   customService.ID,
			Name:       customService.Name,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_CUSTOM_SERVICE}],
			TeamID:     tagrecorder.DomainToTeamID[customService.Domain],
			DomainID:   tagrecorder.DomainToDomainID[customService.Domain],
		}
	}
	return true
}
