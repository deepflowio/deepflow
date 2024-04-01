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
	"gorm.io/gorm/clause"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"

	// "github.com/deepflowio/deepflow/server/controller/db/mysql/query"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChVMDevice struct {
	SubscriberComponent[*message.VMFieldsUpdate, message.VMFieldsUpdate, mysql.VM, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChVMDevice(resourceTypeToIconID map[IconKey]int) *ChVMDevice {
	mng := &ChVMDevice{
		newSubscriberComponent[*message.VMFieldsUpdate, message.VMFieldsUpdate, mysql.VM, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_VM_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChVMDevice) sourceToTarget(source *mysql.VM) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_VM,
		SubType:  source.HType,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_VM,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_VM,
		DeviceID:   source.ID,
		Name:       sourceName,
		UID:        source.UID,
		IconID:     iconID,
		Hostname:   source.Hostname,
		IP:         source.IP,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChVMDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.VMFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.UID.IsDifferent() {
		updateInfo["uid"] = fieldsUpdate.UID.GetNew()
	}
	if fieldsUpdate.Hostname.IsDifferent() {
		updateInfo["hostname"] = fieldsUpdate.Hostname.GetNew()
	}
	if fieldsUpdate.IP.IsDifferent() {
		updateInfo["ip"] = fieldsUpdate.IP.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_VM).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_VM,
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChVMDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChHostDevice struct {
	SubscriberComponent[*message.HostFieldsUpdate, message.HostFieldsUpdate, mysql.Host, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChHostDevice(resourceTypeToIconID map[IconKey]int) *ChHostDevice {
	mng := &ChHostDevice{
		newSubscriberComponent[*message.HostFieldsUpdate, message.HostFieldsUpdate, mysql.Host, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_HOST_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChHostDevice) sourceToTarget(source *mysql.Host) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_HOST,
		SubType:  source.HType,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_HOST,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_HOST,
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
		Hostname:   source.Hostname,
		IP:         source.IP,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChHostDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.HostFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.UID.IsDifferent() {
		updateInfo["uid"] = fieldsUpdate.UID.GetNew()
	}
	if fieldsUpdate.Hostname.IsDifferent() {
		updateInfo["hostname"] = fieldsUpdate.Hostname.GetNew()
	}
	if fieldsUpdate.IP.IsDifferent() {
		updateInfo["ip"] = fieldsUpdate.IP.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_HOST).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_HOST,
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChHostDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChVRouterDevice struct {
	SubscriberComponent[*message.VRouterFieldsUpdate, message.VRouterFieldsUpdate, mysql.VRouter, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChVRouterDevice(resourceTypeToIconID map[IconKey]int) *ChVRouterDevice {
	mng := &ChVRouterDevice{
		newSubscriberComponent[*message.VRouterFieldsUpdate, message.VRouterFieldsUpdate, mysql.VRouter, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_VROUTER_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChVRouterDevice) sourceToTarget(source *mysql.VRouter) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_VGW,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_VROUTER,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_VROUTER,
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChVRouterDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.VRouterFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_VROUTER).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_VROUTER,
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChVRouterDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChDHCPPortDevice struct {
	SubscriberComponent[*message.DHCPPortFieldsUpdate, message.DHCPPortFieldsUpdate, mysql.DHCPPort, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChDHCPPortDevice(resourceTypeToIconID map[IconKey]int) *ChDHCPPortDevice {
	mng := &ChDHCPPortDevice{
		newSubscriberComponent[*message.DHCPPortFieldsUpdate, message.DHCPPortFieldsUpdate, mysql.DHCPPort, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_DHCP_PORT_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChDHCPPortDevice) sourceToTarget(source *mysql.DHCPPort) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_DHCP_PORT,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_DHCP_PORT,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_DHCP_PORT,
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChDHCPPortDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.DHCPPortFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_DHCP_PORT).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_DHCP_PORT,
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChDHCPPortDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChNATGatewayDevice struct {
	SubscriberComponent[*message.NATGatewayFieldsUpdate, message.NATGatewayFieldsUpdate, mysql.NATGateway, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChNATGatewayDevice(resourceTypeToIconID map[IconKey]int) *ChNATGatewayDevice {
	mng := &ChNATGatewayDevice{
		newSubscriberComponent[*message.NATGatewayFieldsUpdate, message.NATGatewayFieldsUpdate, mysql.NATGateway, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_NAT_GATEWAY_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChNATGatewayDevice) sourceToTarget(source *mysql.NATGateway) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_NAT_GATEWAY,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_NAT_GATEWAY,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_NAT_GATEWAY,
		DeviceID:   source.ID,
		Name:       sourceName,
		UID:        source.UID,
		IconID:     iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChNATGatewayDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.NATGatewayFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.UID.IsDifferent() {
		updateInfo["uid"] = fieldsUpdate.UID.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_NAT_GATEWAY).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_NAT_GATEWAY,
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChNATGatewayDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChLBDevice struct {
	SubscriberComponent[*message.LBFieldsUpdate, message.LBFieldsUpdate, mysql.LB, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChLBDevice(resourceTypeToIconID map[IconKey]int) *ChLBDevice {
	mng := &ChLBDevice{
		newSubscriberComponent[*message.LBFieldsUpdate, message.LBFieldsUpdate, mysql.LB, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_LB_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChLBDevice) sourceToTarget(source *mysql.LB) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_LB,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_LB,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_LB,
		DeviceID:   source.ID,
		Name:       sourceName,
		UID:        source.UID,
		IconID:     iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChLBDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.LBFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.UID.IsDifferent() {
		updateInfo["uid"] = fieldsUpdate.UID.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_LB).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_LB,
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChLBDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChRDSInstanceDevice struct {
	SubscriberComponent[*message.RDSInstanceFieldsUpdate, message.RDSInstanceFieldsUpdate, mysql.RDSInstance, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChRDSInstanceDevice(resourceTypeToIconID map[IconKey]int) *ChRDSInstanceDevice {
	mng := &ChRDSInstanceDevice{
		newSubscriberComponent[*message.RDSInstanceFieldsUpdate, message.RDSInstanceFieldsUpdate, mysql.RDSInstance, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_RDS_INSTANCE_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChRDSInstanceDevice) sourceToTarget(source *mysql.RDSInstance) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_RDS,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_RDS_INSTANCE,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_RDS_INSTANCE,
		DeviceID:   source.ID,
		Name:       sourceName,
		UID:        source.UID,
		IconID:     iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChRDSInstanceDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.RDSInstanceFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.UID.IsDifferent() {
		updateInfo["uid"] = fieldsUpdate.UID.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_RDS_INSTANCE).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_RDS_INSTANCE,
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChRDSInstanceDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChRedisInstanceDevice struct {
	SubscriberComponent[*message.RedisInstanceFieldsUpdate, message.RedisInstanceFieldsUpdate, mysql.RedisInstance, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChRedisInstanceDevice(resourceTypeToIconID map[IconKey]int) *ChRedisInstanceDevice {
	mng := &ChRedisInstanceDevice{
		newSubscriberComponent[*message.RedisInstanceFieldsUpdate, message.RedisInstanceFieldsUpdate, mysql.RedisInstance, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_REDIS_INSTANCE_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChRedisInstanceDevice) sourceToTarget(source *mysql.RedisInstance) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_REDIS,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
		DeviceID:   source.ID,
		Name:       sourceName,
		UID:        source.UID,
		IconID:     iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChRedisInstanceDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.RedisInstanceFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.UID.IsDifferent() {
		updateInfo["uid"] = fieldsUpdate.UID.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_REDIS_INSTANCE).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChRedisInstanceDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodServiceDevice struct {
	SubscriberComponent[*message.PodServiceFieldsUpdate, message.PodServiceFieldsUpdate, mysql.PodService, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodServiceDevice(resourceTypeToIconID map[IconKey]int) *ChPodServiceDevice {
	mng := &ChPodServiceDevice{
		newSubscriberComponent[*message.PodServiceFieldsUpdate, message.PodServiceFieldsUpdate, mysql.PodService, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodServiceDevice) sourceToTarget(source *mysql.PodService) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_SERVICE,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}
	// pod_service
	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD_SERVICE,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_POD_SERVICE,
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
	})

	// service
	keys = append(keys, DeviceKey{DeviceType: CH_DEVICE_TYPE_SERVICE,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: CH_DEVICE_TYPE_SERVICE,
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodServiceDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.PodServiceFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_POD_SERVICE).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD_SERVICE,
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodServiceDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodDevice struct {
	SubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysql.Pod, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodDevice(resourceTypeToIconID map[IconKey]int) *ChPodDevice {
	mng := &ChPodDevice{
		newSubscriberComponent[*message.PodFieldsUpdate, message.PodFieldsUpdate, mysql.Pod, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodDevice) sourceToTarget(source *mysql.Pod) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_POD,
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.PodFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_POD).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD,
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {

	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodGroupDevice struct {
	SubscriberComponent[*message.PodGroupFieldsUpdate, message.PodGroupFieldsUpdate, mysql.PodGroup, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodGroupDevice(resourceTypeToIconID map[IconKey]int) *ChPodGroupDevice {
	mng := &ChPodGroupDevice{
		newSubscriberComponent[*message.PodGroupFieldsUpdate, message.PodGroupFieldsUpdate, mysql.PodGroup, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_POD_GROUP_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodGroupDevice) sourceToTarget(source *mysql.PodGroup) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_GROUP,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: RESOURCE_POD_GROUP_TYPE_MAP[source.Type],
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: RESOURCE_POD_GROUP_TYPE_MAP[source.Type],
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodGroupDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.PodGroupFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		podGroupType := fieldsUpdate.Type.GetNew()
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, RESOURCE_POD_GROUP_TYPE_MAP[podGroupType]).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: RESOURCE_POD_GROUP_TYPE_MAP[podGroupType],
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodGroupDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodNodeDevice struct {
	SubscriberComponent[*message.PodNodeFieldsUpdate, message.PodNodeFieldsUpdate, mysql.PodNode, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNodeDevice(resourceTypeToIconID map[IconKey]int) *ChPodNodeDevice {
	mng := &ChPodNodeDevice{
		newSubscriberComponent[*message.PodNodeFieldsUpdate, message.PodNodeFieldsUpdate, mysql.PodNode, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_POD_NODE_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodNodeDevice) sourceToTarget(source *mysql.PodNode) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_NODE,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD_NODE,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_POD_NODE,
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNodeDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.PodNodeFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_POD_NODE).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD_NODE,
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodNodeDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChProcessDevice struct {
	SubscriberComponent[*message.ProcessFieldsUpdate, message.ProcessFieldsUpdate, mysql.Process, mysql.ChDevice, DeviceKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChProcessDevice(resourceTypeToIconID map[IconKey]int) *ChProcessDevice {
	mng := &ChProcessDevice{
		newSubscriberComponent[*message.ProcessFieldsUpdate, message.ProcessFieldsUpdate, mysql.Process, mysql.ChDevice, DeviceKey](
			common.RESOURCE_TYPE_PROCESS_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChProcessDevice) sourceToTarget(source *mysql.Process) (keys []DeviceKey, targets []mysql.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_GPROCESS,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: CH_DEVICE_TYPE_GPROCESS,
		DeviceID: source.ID})
	targets = append(targets, mysql.ChDevice{
		DeviceType: CH_DEVICE_TYPE_GPROCESS,
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChProcessDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.ProcessFieldsUpdate) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	// if oldItem.IconID != newItem.IconID { // TODO need icon id
	// 	updateInfo["icon_id"] = newItem.IconID
	// }
	if len(updateInfo) > 0 {
		var chItem mysql.ChDevice
		mysql.Db.Where("deviceid = ? and devicetype = ?", sourceID, CH_DEVICE_TYPE_GPROCESS).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: CH_DEVICE_TYPE_GPROCESS,
			DeviceID: sourceID})
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChProcessDevice) softDeletedTargetsUpdated(targets []mysql.ChDevice) {
	mysql.Db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}
