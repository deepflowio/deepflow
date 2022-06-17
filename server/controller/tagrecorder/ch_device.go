package tagrecorder

import (
	"server/controller/common"
	"server/controller/db/mysql"
)

type ChDevice struct {
	UpdaterBase[mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChDevice(resourceTypeToIconID map[IconKey]int) *ChDevice {
	updater := &ChDevice{
		UpdaterBase[mysql.ChDevice, DeviceKey]{
			resourceTypeName: RESOURCE_TYPE_CH_DEVICE,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (d *ChDevice) generateNewData() (map[DeviceKey]mysql.ChDevice, bool) {
	log.Infof("generate data for %s", d.resourceTypeName)
	keyToItem := make(map[DeviceKey]mysql.ChDevice)
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
	d.generateIPData(keyToItem)
	d.generateInternetData(keyToItem)
	return keyToItem, true
}

func (d *ChDevice) generateKey(dbItem mysql.ChDevice) DeviceKey {
	return DeviceKey{
		DeviceType: dbItem.DeviceType,
		DeviceID:   dbItem.DeviceID,
	}
}

func (d *ChDevice) generateUpdateInfo(oldItem, newItem mysql.ChDevice) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID {
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

func (d *ChDevice) generateHostData(keyToItem map[DeviceKey]mysql.ChDevice) bool {
	var hosts []mysql.Host
	err := mysql.Db.Find(&hosts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return false
	}

	for _, host := range hosts {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_HOST,
			DeviceID:   host.ID,
		}
		keyToItem[key] = mysql.ChDevice{
			DeviceType: common.VIF_DEVICE_TYPE_HOST,
			DeviceID:   host.ID,
			Name:       host.Name,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_HOST, SubType: host.HType}],
		}
	}
	return true
}

func (d *ChDevice) generateVMData(keyToItem map[DeviceKey]mysql.ChDevice) bool {
	var vms []mysql.VM
	err := mysql.Db.Find(&vms).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return false
	}

	for _, vm := range vms {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_VM,
			DeviceID:   vm.ID,
		}
		keyToItem[key] = mysql.ChDevice{
			DeviceType: common.VIF_DEVICE_TYPE_VM,
			DeviceID:   vm.ID,
			Name:       vm.Name,
			UID:        vm.UID,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VM, SubType: vm.HType}],
		}
	}
	return true
}

func (d *ChDevice) generateVRouterData(keyToItem map[DeviceKey]mysql.ChDevice) bool {
	var vrouters []mysql.VRouter
	err := mysql.Db.Find(&vrouters).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return false
	}

	for _, vrouter := range vrouters {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_VROUTER,
			DeviceID:   vrouter.ID,
		}
		keyToItem[key] = mysql.ChDevice{
			DeviceType: common.VIF_DEVICE_TYPE_VROUTER,
			DeviceID:   vrouter.ID,
			Name:       vrouter.Name,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VGW}],
		}
	}
	return true
}

func (d *ChDevice) generateDHCPPortData(keyToItem map[DeviceKey]mysql.ChDevice) bool {
	var dhcpPorts []mysql.DHCPPort
	err := mysql.Db.Find(&dhcpPorts).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return false
	}

	for _, dhcpPort := range dhcpPorts {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_DHCP_PORT,
			DeviceID:   dhcpPort.ID,
		}
		keyToItem[key] = mysql.ChDevice{
			DeviceType: common.VIF_DEVICE_TYPE_DHCP_PORT,
			DeviceID:   dhcpPort.ID,
			Name:       dhcpPort.Name,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_DHCP_PORT}],
		}
	}
	return true
}

func (d *ChDevice) generateNATGatewayData(keyToItem map[DeviceKey]mysql.ChDevice) bool {
	var natGateways []mysql.NATGateway
	err := mysql.Db.Find(&natGateways).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return false
	}

	for _, natGateway := range natGateways {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_NAT_GATEWAY,
			DeviceID:   natGateway.ID,
		}
		keyToItem[key] = mysql.ChDevice{
			DeviceType: common.VIF_DEVICE_TYPE_NAT_GATEWAY,
			DeviceID:   natGateway.ID,
			Name:       natGateway.Name,
			UID:        natGateway.UID,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_NAT_GATEWAY}],
		}
	}
	return true
}

func (d *ChDevice) generateLBData(keyToItem map[DeviceKey]mysql.ChDevice) bool {
	var lbs []mysql.LB
	err := mysql.Db.Find(&lbs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return false
	}

	for _, lb := range lbs {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_LB,
			DeviceID:   lb.ID,
		}
		keyToItem[key] = mysql.ChDevice{
			DeviceType: common.VIF_DEVICE_TYPE_LB,
			DeviceID:   lb.ID,
			Name:       lb.Name,
			UID:        lb.UID,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_LB}],
		}
	}
	return true
}

func (d *ChDevice) generateRDSInstanceData(keyToItem map[DeviceKey]mysql.ChDevice) bool {
	var rdsInstances []mysql.RDSInstance
	err := mysql.Db.Find(&rdsInstances).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return false
	}

	for _, rdsInstance := range rdsInstances {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_RDS_INSTANCE,
			DeviceID:   rdsInstance.ID,
		}
		keyToItem[key] = mysql.ChDevice{
			DeviceType: common.VIF_DEVICE_TYPE_RDS_INSTANCE,
			DeviceID:   rdsInstance.ID,
			Name:       rdsInstance.Name,
			UID:        rdsInstance.UID,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_RDS}],
		}
	}
	return true
}

func (d *ChDevice) generateRedisInstanceData(keyToItem map[DeviceKey]mysql.ChDevice) bool {
	var redisInstances []mysql.RedisInstance
	err := mysql.Db.Find(&redisInstances).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return false
	}

	for _, redisInstance := range redisInstances {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
			DeviceID:   redisInstance.ID,
		}
		keyToItem[key] = mysql.ChDevice{
			DeviceType: common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
			DeviceID:   redisInstance.ID,
			Name:       redisInstance.Name,
			UID:        redisInstance.UID,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_REDIS}],
		}
	}
	return true
}

func (d *ChDevice) generatePodServiceData(keyToItem map[DeviceKey]mysql.ChDevice) bool {
	var podServices []mysql.PodService
	err := mysql.Db.Find(&podServices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return false
	}

	for _, podService := range podServices {
		// pod_service
		podServiceKey := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_POD_SERVICE,
			DeviceID:   podService.ID,
		}
		keyToItem[podServiceKey] = mysql.ChDevice{
			DeviceType: common.VIF_DEVICE_TYPE_POD_SERVICE,
			DeviceID:   podService.ID,
			Name:       podService.Name,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_SERVICE}],
		}

		// service
		serviceKey := DeviceKey{
			DeviceType: CH_DEVICE_TYPE_SERVICE,
			DeviceID:   podService.ID,
		}
		keyToItem[serviceKey] = mysql.ChDevice{
			DeviceType: CH_DEVICE_TYPE_SERVICE,
			DeviceID:   podService.ID,
			Name:       podService.Name,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_SERVICE}],
		}
	}
	return true
}

func (d *ChDevice) generatePodData(keyToItem map[DeviceKey]mysql.ChDevice) bool {
	var pods []mysql.Pod
	err := mysql.Db.Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return false
	}

	for _, pod := range pods {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_POD,
			DeviceID:   pod.ID,
		}
		keyToItem[key] = mysql.ChDevice{
			DeviceType: common.VIF_DEVICE_TYPE_POD,
			DeviceID:   pod.ID,
			Name:       pod.Name,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD}],
		}
	}
	return true
}

func (d *ChDevice) generatePodGroupData(keyToItem map[DeviceKey]mysql.ChDevice) bool {
	var podGroups []mysql.PodGroup
	err := mysql.Db.Find(&podGroups).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return false
	}

	for _, podGroup := range podGroups {
		key := DeviceKey{
			DeviceType: CH_DEVICE_TYPE_POD_GROUP,
			DeviceID:   podGroup.ID,
		}
		keyToItem[key] = mysql.ChDevice{
			DeviceType: CH_DEVICE_TYPE_POD_GROUP,
			DeviceID:   podGroup.ID,
			Name:       podGroup.Name,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_GROUP}],
		}
	}
	return true
}

func (d *ChDevice) generatePodNodeData(keyToItem map[DeviceKey]mysql.ChDevice) bool {
	var podNodes []mysql.PodNode
	err := mysql.Db.Find(&podNodes).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(d.resourceTypeName, err))
		return false
	}

	for _, podNode := range podNodes {
		key := DeviceKey{
			DeviceType: common.VIF_DEVICE_TYPE_POD_NODE,
			DeviceID:   podNode.ID,
		}
		keyToItem[key] = mysql.ChDevice{
			DeviceType: common.VIF_DEVICE_TYPE_POD_NODE,
			DeviceID:   podNode.ID,
			Name:       podNode.Name,
			IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NODE}],
		}
	}
	return true
}

func (d *ChDevice) generateIPData(keyToItem map[DeviceKey]mysql.ChDevice) {
	key := DeviceKey{
		DeviceType: CH_DEVICE_TYPE_IP,
		DeviceID:   CH_DEVICE_TYPE_IP,
	}
	keyToItem[key] = mysql.ChDevice{
		DeviceType: CH_DEVICE_TYPE_IP,
		DeviceID:   CH_DEVICE_TYPE_IP,
		IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_IP}],
	}
}

func (d *ChDevice) generateInternetData(keyToItem map[DeviceKey]mysql.ChDevice) {
	key := DeviceKey{
		DeviceType: CH_DEVICE_TYPE_INTERNET,
		DeviceID:   CH_DEVICE_TYPE_INTERNET,
	}
	keyToItem[key] = mysql.ChDevice{
		DeviceType: CH_DEVICE_TYPE_INTERNET,
		DeviceID:   CH_DEVICE_TYPE_INTERNET,
		Name:       "Internet",
		IconID:     d.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_INTERNET}],
	}
}
