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
	"slices"

	"gorm.io/gorm/clause"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"

	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChVMDevice struct {
	SubscriberComponent[
		*message.VMAdd,
		message.VMAdd,
		*message.VMFieldsUpdate,
		message.VMFieldsUpdate,
		*message.VMDelete,
		message.VMDelete,
		mysqlmodel.VM,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChVMDevice(resourceTypeToIconID map[IconKey]int) *ChVMDevice {
	mng := &ChVMDevice{
		newSubscriberComponent[
			*message.VMAdd,
			message.VMAdd,
			*message.VMFieldsUpdate,
			message.VMFieldsUpdate,
			*message.VMDelete,
			message.VMDelete,
			mysqlmodel.VM,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_VM_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChVMDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.VM) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
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
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_VM,
		DeviceID:   source.ID,
		Name:       sourceName,
		UID:        source.UID,
		IconID:     iconID,
		Hostname:   source.Hostname,
		IP:         source.IP,
		TeamID:     md.GetTeamID(),
		DomainID:   md.GetDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChVMDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.VMFieldsUpdate, db *mysql.DB) {
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
	if fieldsUpdate.HType.IsDifferent() {
		updateInfo["icon_id"] = c.resourceTypeToIconID[IconKey{
			NodeType: RESOURCE_TYPE_VM,
			SubType:  fieldsUpdate.HType.GetNew(),
		}]
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_VM).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_VM,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChVMDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChHostDevice struct {
	SubscriberComponent[
		*message.HostAdd,
		message.HostAdd,
		*message.HostFieldsUpdate,
		message.HostFieldsUpdate,
		*message.HostDelete,
		message.HostDelete,
		mysqlmodel.Host,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChHostDevice(resourceTypeToIconID map[IconKey]int) *ChHostDevice {
	mng := &ChHostDevice{
		newSubscriberComponent[
			*message.HostAdd,
			message.HostAdd,
			*message.HostFieldsUpdate,
			message.HostFieldsUpdate,
			*message.HostDelete,
			message.HostDelete,
			mysqlmodel.Host,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_HOST_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChHostDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.Host) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
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
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_HOST,
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
		Hostname:   source.Hostname,
		IP:         source.IP,
		TeamID:     md.GetTeamID(),
		DomainID:   md.GetDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChHostDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.HostFieldsUpdate, db *mysql.DB) {
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
	if fieldsUpdate.HType.IsDifferent() {
		updateInfo["icon_id"] = c.resourceTypeToIconID[IconKey{
			NodeType: RESOURCE_TYPE_HOST,
			SubType:  fieldsUpdate.HType.GetNew(),
		}]
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_HOST).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_HOST,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChHostDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {

	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChVRouterDevice struct {
	SubscriberComponent[
		*message.VRouterAdd,
		message.VRouterAdd,
		*message.VRouterFieldsUpdate,
		message.VRouterFieldsUpdate,
		*message.VRouterDelete,
		message.VRouterDelete,
		mysqlmodel.VRouter,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChVRouterDevice(resourceTypeToIconID map[IconKey]int) *ChVRouterDevice {
	mng := &ChVRouterDevice{
		newSubscriberComponent[
			*message.VRouterAdd,
			message.VRouterAdd,
			*message.VRouterFieldsUpdate,
			message.VRouterFieldsUpdate,
			*message.VRouterDelete,
			message.VRouterDelete,
			mysqlmodel.VRouter,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_VROUTER_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChVRouterDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.VRouter) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_VGW,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_VROUTER,
		DeviceID: source.ID})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_VROUTER,
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
		TeamID:     md.GetTeamID(),
		DomainID:   md.GetDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChVRouterDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.VRouterFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_VROUTER).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_VROUTER,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChVRouterDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChDHCPPortDevice struct {
	SubscriberComponent[
		*message.DHCPPortAdd,
		message.DHCPPortAdd,
		*message.DHCPPortFieldsUpdate,
		message.DHCPPortFieldsUpdate,
		*message.DHCPPortDelete,
		message.DHCPPortDelete,
		mysqlmodel.DHCPPort,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChDHCPPortDevice(resourceTypeToIconID map[IconKey]int) *ChDHCPPortDevice {
	mng := &ChDHCPPortDevice{
		newSubscriberComponent[
			*message.DHCPPortAdd,
			message.DHCPPortAdd,
			*message.DHCPPortFieldsUpdate,
			message.DHCPPortFieldsUpdate,
			*message.DHCPPortDelete,
			message.DHCPPortDelete,
			mysqlmodel.DHCPPort,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_DHCP_PORT_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChDHCPPortDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.DHCPPort) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_DHCP_PORT,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_DHCP_PORT,
		DeviceID: source.ID})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_DHCP_PORT,
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
		TeamID:     md.GetTeamID(),
		DomainID:   md.GetDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChDHCPPortDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.DHCPPortFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_DHCP_PORT).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_DHCP_PORT,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChDHCPPortDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChNATGatewayDevice struct {
	SubscriberComponent[
		*message.NATGatewayAdd,
		message.NATGatewayAdd,
		*message.NATGatewayFieldsUpdate,
		message.NATGatewayFieldsUpdate,
		*message.NATGatewayDelete,
		message.NATGatewayDelete,
		mysqlmodel.NATGateway,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChNATGatewayDevice(resourceTypeToIconID map[IconKey]int) *ChNATGatewayDevice {
	mng := &ChNATGatewayDevice{
		newSubscriberComponent[
			*message.NATGatewayAdd,
			message.NATGatewayAdd,
			*message.NATGatewayFieldsUpdate,
			message.NATGatewayFieldsUpdate,
			*message.NATGatewayDelete,
			message.NATGatewayDelete,
			mysqlmodel.NATGateway,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_NAT_GATEWAY_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChNATGatewayDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.NATGateway) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_NAT_GATEWAY,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_NAT_GATEWAY,
		DeviceID: source.ID})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_NAT_GATEWAY,
		DeviceID:   source.ID,
		Name:       sourceName,
		UID:        source.UID,
		IconID:     iconID,
		TeamID:     md.GetTeamID(),
		DomainID:   md.GetDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChNATGatewayDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.NATGatewayFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.UID.IsDifferent() {
		updateInfo["uid"] = fieldsUpdate.UID.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_NAT_GATEWAY).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_NAT_GATEWAY,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChNATGatewayDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChLBDevice struct {
	SubscriberComponent[
		*message.LBAdd,
		message.LBAdd,
		*message.LBFieldsUpdate,
		message.LBFieldsUpdate,
		*message.LBDelete,
		message.LBDelete,
		mysqlmodel.LB,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChLBDevice(resourceTypeToIconID map[IconKey]int) *ChLBDevice {
	mng := &ChLBDevice{
		newSubscriberComponent[
			*message.LBAdd,
			message.LBAdd,
			*message.LBFieldsUpdate,
			message.LBFieldsUpdate,
			*message.LBDelete,
			message.LBDelete,
			mysqlmodel.LB,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_LB_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChLBDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.LB) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_LB,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_LB,
		DeviceID: source.ID})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_LB,
		DeviceID:   source.ID,
		Name:       sourceName,
		UID:        source.UID,
		IconID:     iconID,
		TeamID:     md.GetTeamID(),
		DomainID:   md.GetDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChLBDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.LBFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.UID.IsDifferent() {
		updateInfo["uid"] = fieldsUpdate.UID.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_LB).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_LB,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChLBDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChRDSInstanceDevice struct {
	SubscriberComponent[*message.RDSInstanceAdd,
		message.RDSInstanceAdd,
		*message.RDSInstanceFieldsUpdate,
		message.RDSInstanceFieldsUpdate,
		*message.RDSInstanceDelete,
		message.RDSInstanceDelete,
		mysqlmodel.RDSInstance,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChRDSInstanceDevice(resourceTypeToIconID map[IconKey]int) *ChRDSInstanceDevice {
	mng := &ChRDSInstanceDevice{
		newSubscriberComponent[*message.RDSInstanceAdd,
			message.RDSInstanceAdd,
			*message.RDSInstanceFieldsUpdate,
			message.RDSInstanceFieldsUpdate,
			*message.RDSInstanceDelete,
			message.RDSInstanceDelete,
			mysqlmodel.RDSInstance,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_RDS_INSTANCE_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChRDSInstanceDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.RDSInstance) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_RDS,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_RDS_INSTANCE,
		DeviceID: source.ID})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_RDS_INSTANCE,
		DeviceID:   source.ID,
		Name:       sourceName,
		UID:        source.UID,
		IconID:     iconID,
		TeamID:     md.GetTeamID(),
		DomainID:   md.GetDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChRDSInstanceDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.RDSInstanceFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.UID.IsDifferent() {
		updateInfo["uid"] = fieldsUpdate.UID.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_RDS_INSTANCE).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_RDS_INSTANCE,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChRDSInstanceDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChRedisInstanceDevice struct {
	SubscriberComponent[*message.RedisInstanceAdd,
		message.RedisInstanceAdd,
		*message.RedisInstanceFieldsUpdate,
		message.RedisInstanceFieldsUpdate,
		*message.RedisInstanceDelete,
		message.RedisInstanceDelete,
		mysqlmodel.RedisInstance,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChRedisInstanceDevice(resourceTypeToIconID map[IconKey]int) *ChRedisInstanceDevice {
	mng := &ChRedisInstanceDevice{
		newSubscriberComponent[*message.RedisInstanceAdd,
			message.RedisInstanceAdd,
			*message.RedisInstanceFieldsUpdate,
			message.RedisInstanceFieldsUpdate,
			*message.RedisInstanceDelete,
			message.RedisInstanceDelete,
			mysqlmodel.RedisInstance,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_REDIS_INSTANCE_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChRedisInstanceDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.RedisInstance) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_REDIS,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
		DeviceID: source.ID})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType: common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
		DeviceID:   source.ID,
		Name:       sourceName,
		UID:        source.UID,
		IconID:     iconID,
		TeamID:     md.GetTeamID(),
		DomainID:   md.GetDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChRedisInstanceDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.RedisInstanceFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.UID.IsDifferent() {
		updateInfo["uid"] = fieldsUpdate.UID.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_REDIS_INSTANCE).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChRedisInstanceDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodServiceDevice struct {
	SubscriberComponent[*message.PodServiceAdd,
		message.PodServiceAdd,
		*message.PodServiceFieldsUpdate,
		message.PodServiceFieldsUpdate,
		*message.PodServiceDelete,
		message.PodServiceDelete,
		mysqlmodel.PodService,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodServiceDevice(resourceTypeToIconID map[IconKey]int) *ChPodServiceDevice {
	mng := &ChPodServiceDevice{
		newSubscriberComponent[*message.PodServiceAdd,
			message.PodServiceAdd,
			*message.PodServiceFieldsUpdate,
			message.PodServiceFieldsUpdate,
			*message.PodServiceDelete,
			message.PodServiceDelete,
			mysqlmodel.PodService,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_POD_SERVICE_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodServiceDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.PodService) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
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
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType:  common.VIF_DEVICE_TYPE_POD_SERVICE,
		DeviceID:    source.ID,
		Name:        sourceName,
		IconID:      iconID,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	})

	// service
	keys = append(keys, DeviceKey{DeviceType: CH_DEVICE_TYPE_SERVICE,
		DeviceID: source.ID})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType:  CH_DEVICE_TYPE_SERVICE,
		DeviceID:    source.ID,
		Name:        sourceName,
		IconID:      iconID,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodServiceDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.PodServiceFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_POD_SERVICE).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD_SERVICE,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodServiceDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodDevice struct {
	SubscriberComponent[*message.PodAdd,
		message.PodAdd,
		*message.PodFieldsUpdate,
		message.PodFieldsUpdate,
		*message.PodDelete,
		message.PodDelete,
		mysqlmodel.Pod,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodDevice(resourceTypeToIconID map[IconKey]int) *ChPodDevice {
	mng := &ChPodDevice{
		newSubscriberComponent[*message.PodAdd,
			message.PodAdd,
			*message.PodFieldsUpdate,
			message.PodFieldsUpdate,
			*message.PodDelete,
			message.PodDelete,
			mysqlmodel.Pod,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_POD_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.Pod) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD,
		DeviceID: source.ID})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType:  common.VIF_DEVICE_TYPE_POD,
		DeviceID:    source.ID,
		Name:        sourceName,
		IconID:      iconID,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.PodFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_POD).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodGroupDevice struct {
	SubscriberComponent[*message.PodGroupAdd,
		message.PodGroupAdd,
		*message.PodGroupFieldsUpdate,
		message.PodGroupFieldsUpdate,
		*message.PodGroupDelete,
		message.PodGroupDelete,
		mysqlmodel.PodGroup,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodGroupDevice(resourceTypeToIconID map[IconKey]int) *ChPodGroupDevice {
	mng := &ChPodGroupDevice{
		newSubscriberComponent[*message.PodGroupAdd,
			message.PodGroupAdd,
			*message.PodGroupFieldsUpdate,
			message.PodGroupFieldsUpdate,
			*message.PodGroupDelete,
			message.PodGroupDelete,
			mysqlmodel.PodGroup,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_POD_GROUP_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodGroupDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.PodGroup) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_GROUP,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: RESOURCE_POD_GROUP_TYPE_MAP[source.Type],
		DeviceID: source.ID})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType:  RESOURCE_POD_GROUP_TYPE_MAP[source.Type],
		DeviceID:    source.ID,
		Name:        sourceName,
		IconID:      iconID,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodGroupDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.PodGroupFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})

	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if len(updateInfo) > 0 {
		podGroupType := fieldsUpdate.Type.GetNew()
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, RESOURCE_POD_GROUP_TYPE_MAP[podGroupType]).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: RESOURCE_POD_GROUP_TYPE_MAP[podGroupType],
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodGroupDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodNodeDevice struct {
	SubscriberComponent[*message.PodNodeAdd,
		message.PodNodeAdd,
		*message.PodNodeFieldsUpdate,
		message.PodNodeFieldsUpdate,
		*message.PodNodeDelete,
		message.PodNodeDelete,
		mysqlmodel.PodNode,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNodeDevice(resourceTypeToIconID map[IconKey]int) *ChPodNodeDevice {
	mng := &ChPodNodeDevice{
		newSubscriberComponent[*message.PodNodeAdd,
			message.PodNodeAdd,
			*message.PodNodeFieldsUpdate,
			message.PodNodeFieldsUpdate,
			*message.PodNodeDelete,
			message.PodNodeDelete,
			mysqlmodel.PodNode,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_POD_NODE_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodNodeDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.PodNode) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_NODE,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD_NODE,
		DeviceID: source.ID})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType:  common.VIF_DEVICE_TYPE_POD_NODE,
		DeviceID:    source.ID,
		Name:        sourceName,
		IconID:      iconID,
		Hostname:    source.Hostname,
		IP:          source.IP,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNodeDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.PodNodeFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if fieldsUpdate.Hostname.IsDifferent() {
		updateInfo["hostname"] = fieldsUpdate.Hostname.GetNew()
	}
	if fieldsUpdate.IP.IsDifferent() {
		updateInfo["ip"] = fieldsUpdate.IP.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_POD_NODE).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD_NODE,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodNodeDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodClusterDevice struct {
	SubscriberComponent[
		*message.PodClusterAdd,
		message.PodClusterAdd,
		*message.PodClusterFieldsUpdate,
		message.PodClusterFieldsUpdate,
		*message.PodClusterDelete,
		message.PodClusterDelete,
		mysqlmodel.PodCluster,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodClusterDevice(resourceTypeToIconID map[IconKey]int) *ChPodClusterDevice {
	mng := &ChPodClusterDevice{
		newSubscriberComponent[
			*message.PodClusterAdd,
			message.PodClusterAdd,
			*message.PodClusterFieldsUpdate,
			message.PodClusterFieldsUpdate,
			*message.PodClusterDelete,
			message.PodClusterDelete,
			mysqlmodel.PodCluster,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_POD_CLUSTER_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChPodClusterDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.PodCluster) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_CLUSTER,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD_NODE,
		DeviceID: source.ID})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType:  common.VIF_DEVICE_TYPE_POD_CLUSTER,
		DeviceID:    source.ID,
		Name:        sourceName,
		IconID:      iconID,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodClusterDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.PodClusterFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, common.VIF_DEVICE_TYPE_POD_NODE).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD_CLUSTER,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodClusterDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChProcessDevice struct {
	SubscriberComponent[
		*message.ProcessAdd,
		message.ProcessAdd,
		*message.ProcessFieldsUpdate,
		message.ProcessFieldsUpdate,
		*message.ProcessDelete,
		message.ProcessDelete,
		mysqlmodel.Process,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChProcessDevice(resourceTypeToIconID map[IconKey]int) *ChProcessDevice {
	mng := &ChProcessDevice{
		newSubscriberComponent[
			*message.ProcessAdd,
			message.ProcessAdd,
			*message.ProcessFieldsUpdate,
			message.ProcessFieldsUpdate,
			*message.ProcessDelete,
			message.ProcessDelete,
			mysqlmodel.Process,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_PROCESS_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	mng.hookers[hookerDeletePage] = mng
	mng.softDelete = true
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChProcessDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.Process) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_GPROCESS,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}
	gid := int(source.GID)
	keys = append(keys, DeviceKey{DeviceType: CH_DEVICE_TYPE_GPROCESS,
		DeviceID: gid})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType:  CH_DEVICE_TYPE_GPROCESS,
		DeviceID:    gid,
		Name:        sourceName,
		IconID:      iconID,
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChProcessDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.ProcessFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})
	gid := int(fieldsUpdate.GID.GetNew())
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", gid, CH_DEVICE_TYPE_GPROCESS).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: CH_DEVICE_TYPE_GPROCESS,
			DeviceID: gid}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChProcessDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

func (c *ChProcessDevice) beforeDeletePage(dbData []*mysqlmodel.Process, msg *message.ProcessDelete) []*mysqlmodel.Process {
	gids := msg.GetAddition().(*message.ProcessDeleteAddition).DeletedGIDs
	newDatas := []*mysqlmodel.Process{}
	for _, item := range dbData {
		if slices.Contains(gids, item.GID) {
			newDatas = append(newDatas, item)
		}
	}
	return newDatas
}

type ChCustomServiceDevice struct {
	SubscriberComponent[
		*message.CustomServiceAdd,
		message.CustomServiceAdd,
		*message.CustomServiceFieldsUpdate,
		message.CustomServiceFieldsUpdate,
		*message.CustomServiceDelete,
		message.CustomServiceDelete,
		mysqlmodel.CustomService,
		mysqlmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChCustomServiceDevice(resourceTypeToIconID map[IconKey]int) *ChCustomServiceDevice {
	mng := &ChCustomServiceDevice{
		newSubscriberComponent[
			*message.CustomServiceAdd,
			message.CustomServiceAdd,
			*message.CustomServiceFieldsUpdate,
			message.CustomServiceFieldsUpdate,
			*message.CustomServiceDelete,
			message.CustomServiceDelete,
			mysqlmodel.CustomService,
			mysqlmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_CUSTOM_SERVICE_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChCustomServiceDevice) sourceToTarget(md *message.Metadata, source *mysqlmodel.CustomService) (keys []DeviceKey, targets []mysqlmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_CUSTOM_SERVICE,
	}]
	sourceName := source.Name
	keys = append(keys, DeviceKey{DeviceType: CH_DEVICE_TYPE_CUSTOM_SERVICE,
		DeviceID: source.ID})
	targets = append(targets, mysqlmodel.ChDevice{
		DeviceType: CH_DEVICE_TYPE_CUSTOM_SERVICE,
		DeviceID:   source.ID,
		Name:       sourceName,
		IconID:     iconID,
		TeamID:     md.GetTeamID(),
		DomainID:   md.GetDomainID(),
	})
	return
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChCustomServiceDevice) onResourceUpdated(sourceID int, fieldsUpdate *message.CustomServiceFieldsUpdate, db *mysql.DB) {
	updateInfo := make(map[string]interface{})
	if fieldsUpdate.Name.IsDifferent() {
		updateInfo["name"] = fieldsUpdate.Name.GetNew()
	}
	if len(updateInfo) > 0 {
		var chItem mysqlmodel.ChDevice
		db.Where("deviceid = ? and devicetype = ?", sourceID, CH_DEVICE_TYPE_CUSTOM_SERVICE).First(&chItem)
		c.SubscriberComponent.dbOperator.update(chItem, updateInfo, DeviceKey{DeviceType: CH_DEVICE_TYPE_CUSTOM_SERVICE,
			DeviceID: sourceID}, db)
	}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChCustomServiceDevice) softDeletedTargetsUpdated(targets []mysqlmodel.ChDevice, db *mysql.DB) {
}
