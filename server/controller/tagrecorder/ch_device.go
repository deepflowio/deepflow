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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"

	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChVMDevice struct {
	SubscriberComponent[
		*message.AddedVMs,
		message.AddedVMs,
		*message.UpdatedVM,
		message.UpdatedVM,
		*message.DeletedVMs,
		message.DeletedVMs,
		metadbmodel.VM,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChVMDevice(resourceTypeToIconID map[IconKey]int) *ChVMDevice {
	mng := &ChVMDevice{
		newSubscriberComponent[
			*message.AddedVMs,
			message.AddedVMs,
			*message.UpdatedVM,
			message.UpdatedVM,
			*message.DeletedVMs,
			message.DeletedVMs,
			metadbmodel.VM,
			metadbmodel.ChDevice,
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
func (c *ChVMDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.VM) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
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
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChVMDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedVM) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChVMDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChHostDevice struct {
	SubscriberComponent[
		*message.AddedHosts,
		message.AddedHosts,
		*message.UpdatedHost,
		message.UpdatedHost,
		*message.DeletedHosts,
		message.DeletedHosts,
		metadbmodel.Host,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChHostDevice(resourceTypeToIconID map[IconKey]int) *ChHostDevice {
	mng := &ChHostDevice{
		newSubscriberComponent[
			*message.AddedHosts,
			message.AddedHosts,
			*message.UpdatedHost,
			message.UpdatedHost,
			*message.DeletedHosts,
			message.DeletedHosts,
			metadbmodel.Host,
			metadbmodel.ChDevice,
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
func (c *ChHostDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.Host) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
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
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChHostDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedHost) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChHostDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {

	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChVRouterDevice struct {
	SubscriberComponent[
		*message.AddedVRouters,
		message.AddedVRouters,
		*message.UpdatedVRouter,
		message.UpdatedVRouter,
		*message.DeletedVRouters,
		message.DeletedVRouters,
		metadbmodel.VRouter,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChVRouterDevice(resourceTypeToIconID map[IconKey]int) *ChVRouterDevice {
	mng := &ChVRouterDevice{
		newSubscriberComponent[
			*message.AddedVRouters,
			message.AddedVRouters,
			*message.UpdatedVRouter,
			message.UpdatedVRouter,
			*message.DeletedVRouters,
			message.DeletedVRouters,
			metadbmodel.VRouter,
			metadbmodel.ChDevice,
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
func (c *ChVRouterDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.VRouter) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_VGW,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_VROUTER,
		DeviceID: source.ID})
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChVRouterDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedVRouter) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChVRouterDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChDHCPPortDevice struct {
	SubscriberComponent[
		*message.AddedDHCPPorts,
		message.AddedDHCPPorts,
		*message.UpdatedDHCPPort,
		message.UpdatedDHCPPort,
		*message.DeletedDHCPPorts,
		message.DeletedDHCPPorts,
		metadbmodel.DHCPPort,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChDHCPPortDevice(resourceTypeToIconID map[IconKey]int) *ChDHCPPortDevice {
	mng := &ChDHCPPortDevice{
		newSubscriberComponent[
			*message.AddedDHCPPorts,
			message.AddedDHCPPorts,
			*message.UpdatedDHCPPort,
			message.UpdatedDHCPPort,
			*message.DeletedDHCPPorts,
			message.DeletedDHCPPorts,
			metadbmodel.DHCPPort,
			metadbmodel.ChDevice,
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
func (c *ChDHCPPortDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.DHCPPort) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_DHCP_PORT,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_DHCP_PORT,
		DeviceID: source.ID})
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChDHCPPortDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedDHCPPort) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChDHCPPortDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChNATGatewayDevice struct {
	SubscriberComponent[
		*message.AddedNATGateways,
		message.AddedNATGateways,
		*message.UpdatedNATGateway,
		message.UpdatedNATGateway,
		*message.DeletedNATGateways,
		message.DeletedNATGateways,
		metadbmodel.NATGateway,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChNATGatewayDevice(resourceTypeToIconID map[IconKey]int) *ChNATGatewayDevice {
	mng := &ChNATGatewayDevice{
		newSubscriberComponent[
			*message.AddedNATGateways,
			message.AddedNATGateways,
			*message.UpdatedNATGateway,
			message.UpdatedNATGateway,
			*message.DeletedNATGateways,
			message.DeletedNATGateways,
			metadbmodel.NATGateway,
			metadbmodel.ChDevice,
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
func (c *ChNATGatewayDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.NATGateway) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_NAT_GATEWAY,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_NAT_GATEWAY,
		DeviceID: source.ID})
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChNATGatewayDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedNATGateway) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChNATGatewayDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChLBDevice struct {
	SubscriberComponent[
		*message.AddedLBs,
		message.AddedLBs,
		*message.UpdatedLB,
		message.UpdatedLB,
		*message.DeletedLBs,
		message.DeletedLBs,
		metadbmodel.LB,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChLBDevice(resourceTypeToIconID map[IconKey]int) *ChLBDevice {
	mng := &ChLBDevice{
		newSubscriberComponent[
			*message.AddedLBs,
			message.AddedLBs,
			*message.UpdatedLB,
			message.UpdatedLB,
			*message.DeletedLBs,
			message.DeletedLBs,
			metadbmodel.LB,
			metadbmodel.ChDevice,
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
func (c *ChLBDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.LB) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_LB,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_LB,
		DeviceID: source.ID})
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChLBDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedLB) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChLBDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChRDSInstanceDevice struct {
	SubscriberComponent[*message.AddedRDSInstances,
		message.AddedRDSInstances,
		*message.UpdatedRDSInstance,
		message.UpdatedRDSInstance,
		*message.DeletedRDSInstances,
		message.DeletedRDSInstances,
		metadbmodel.RDSInstance,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChRDSInstanceDevice(resourceTypeToIconID map[IconKey]int) *ChRDSInstanceDevice {
	mng := &ChRDSInstanceDevice{
		newSubscriberComponent[*message.AddedRDSInstances,
			message.AddedRDSInstances,
			*message.UpdatedRDSInstance,
			message.UpdatedRDSInstance,
			*message.DeletedRDSInstances,
			message.DeletedRDSInstances,
			metadbmodel.RDSInstance,
			metadbmodel.ChDevice,
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
func (c *ChRDSInstanceDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.RDSInstance) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_RDS,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_RDS_INSTANCE,
		DeviceID: source.ID})
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChRDSInstanceDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedRDSInstance) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChRDSInstanceDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChRedisInstanceDevice struct {
	SubscriberComponent[*message.AddedRedisInstances,
		message.AddedRedisInstances,
		*message.UpdatedRedisInstance,
		message.UpdatedRedisInstance,
		*message.DeletedRedisInstances,
		message.DeletedRedisInstances,
		metadbmodel.RedisInstance,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChRedisInstanceDevice(resourceTypeToIconID map[IconKey]int) *ChRedisInstanceDevice {
	mng := &ChRedisInstanceDevice{
		newSubscriberComponent[*message.AddedRedisInstances,
			message.AddedRedisInstances,
			*message.UpdatedRedisInstance,
			message.UpdatedRedisInstance,
			*message.DeletedRedisInstances,
			message.DeletedRedisInstances,
			metadbmodel.RedisInstance,
			metadbmodel.ChDevice,
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
func (c *ChRedisInstanceDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.RedisInstance) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_REDIS,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
		DeviceID: source.ID})
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChRedisInstanceDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedRedisInstance) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChRedisInstanceDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodServiceDevice struct {
	SubscriberComponent[*message.AddedPodServices,
		message.AddedPodServices,
		*message.UpdatedPodService,
		message.UpdatedPodService,
		*message.DeletedPodServices,
		message.DeletedPodServices,
		metadbmodel.PodService,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodServiceDevice(resourceTypeToIconID map[IconKey]int) *ChPodServiceDevice {
	mng := &ChPodServiceDevice{
		newSubscriberComponent[*message.AddedPodServices,
			message.AddedPodServices,
			*message.UpdatedPodService,
			message.UpdatedPodService,
			*message.DeletedPodServices,
			message.DeletedPodServices,
			metadbmodel.PodService,
			metadbmodel.ChDevice,
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
func (c *ChPodServiceDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.PodService) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
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
	targets = append(targets, metadbmodel.ChDevice{
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
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChPodServiceDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPodService) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodServiceDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodDevice struct {
	SubscriberComponent[*message.AddedPods,
		message.AddedPods,
		*message.UpdatedPod,
		message.UpdatedPod,
		*message.DeletedPods,
		message.DeletedPods,
		metadbmodel.Pod,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodDevice(resourceTypeToIconID map[IconKey]int) *ChPodDevice {
	mng := &ChPodDevice{
		newSubscriberComponent[*message.AddedPods,
			message.AddedPods,
			*message.UpdatedPod,
			message.UpdatedPod,
			*message.DeletedPods,
			message.DeletedPods,
			metadbmodel.Pod,
			metadbmodel.ChDevice,
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
func (c *ChPodDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.Pod) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD,
		DeviceID: source.ID})
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChPodDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPod) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodGroupDevice struct {
	SubscriberComponent[*message.AddedPodGroups,
		message.AddedPodGroups,
		*message.UpdatedPodGroup,
		message.UpdatedPodGroup,
		*message.DeletedPodGroups,
		message.DeletedPodGroups,
		metadbmodel.PodGroup,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodGroupDevice(resourceTypeToIconID map[IconKey]int) *ChPodGroupDevice {
	mng := &ChPodGroupDevice{
		newSubscriberComponent[*message.AddedPodGroups,
			message.AddedPodGroups,
			*message.UpdatedPodGroup,
			message.UpdatedPodGroup,
			*message.DeletedPodGroups,
			message.DeletedPodGroups,
			metadbmodel.PodGroup,
			metadbmodel.ChDevice,
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
func (c *ChPodGroupDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.PodGroup) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_GROUP,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.RESOURCE_POD_GROUP_TYPE_MAP[source.Type],
		DeviceID: source.ID})
	targets = append(targets, metadbmodel.ChDevice{
		DeviceType:  common.RESOURCE_POD_GROUP_TYPE_MAP[source.Type],
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
func (c *ChPodGroupDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPodGroup) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodGroupDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodNodeDevice struct {
	SubscriberComponent[*message.AddedPodNodes,
		message.AddedPodNodes,
		*message.UpdatedPodNode,
		message.UpdatedPodNode,
		*message.DeletedPodNodes,
		message.DeletedPodNodes,
		metadbmodel.PodNode,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNodeDevice(resourceTypeToIconID map[IconKey]int) *ChPodNodeDevice {
	mng := &ChPodNodeDevice{
		newSubscriberComponent[*message.AddedPodNodes,
			message.AddedPodNodes,
			*message.UpdatedPodNode,
			message.UpdatedPodNode,
			*message.DeletedPodNodes,
			message.DeletedPodNodes,
			metadbmodel.PodNode,
			metadbmodel.ChDevice,
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
func (c *ChPodNodeDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.PodNode) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_NODE,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD_NODE,
		DeviceID: source.ID})
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChPodNodeDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPodNode) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodNodeDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChPodClusterDevice struct {
	SubscriberComponent[
		*message.AddedPodClusters,
		message.AddedPodClusters,
		*message.UpdatedPodCluster,
		message.UpdatedPodCluster,
		*message.DeletedPodClusters,
		message.DeletedPodClusters,
		metadbmodel.PodCluster,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodClusterDevice(resourceTypeToIconID map[IconKey]int) *ChPodClusterDevice {
	mng := &ChPodClusterDevice{
		newSubscriberComponent[
			*message.AddedPodClusters,
			message.AddedPodClusters,
			*message.UpdatedPodCluster,
			message.UpdatedPodCluster,
			*message.DeletedPodClusters,
			message.DeletedPodClusters,
			metadbmodel.PodCluster,
			metadbmodel.ChDevice,
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
func (c *ChPodClusterDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.PodCluster) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_POD_CLUSTER,
	}]
	sourceName := source.Name
	if source.DeletedAt.Valid {
		sourceName += " (deleted)"
	}

	keys = append(keys, DeviceKey{DeviceType: common.VIF_DEVICE_TYPE_POD_CLUSTER,
		DeviceID: source.ID})
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChPodClusterDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPodCluster) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodClusterDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

type ChProcessDevice struct {
	SubscriberComponent[
		*message.AddedProcesses,
		message.AddedProcesses,
		*message.UpdatedProcess,
		message.UpdatedProcess,
		*message.DeletedProcesses,
		message.DeletedProcesses,
		metadbmodel.Process,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChProcessDevice(resourceTypeToIconID map[IconKey]int) *ChProcessDevice {
	mng := &ChProcessDevice{
		newSubscriberComponent[
			*message.AddedProcesses,
			message.AddedProcesses,
			*message.UpdatedProcess,
			message.UpdatedProcess,
			*message.DeletedProcesses,
			message.DeletedProcesses,
			metadbmodel.Process,
			metadbmodel.ChDevice,
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
func (c *ChProcessDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.Process) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
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
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChProcessDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedProcess) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChProcessDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceid"}, {Name: "devicetype"}},
		DoUpdates: clause.AssignmentColumns([]string{"name"}),
	}).Create(&targets)
}

func (c *ChProcessDevice) beforeDeletePage(dbData []*metadbmodel.Process, msg *message.DeletedProcesses) []*metadbmodel.Process {
	gids := msg.GetAddition().(*message.ProcessDeleteAddition).DeletedGIDs
	newDatas := []*metadbmodel.Process{}
	for _, item := range dbData {
		if slices.Contains(gids, item.GID) {
			newDatas = append(newDatas, item)
		}
	}
	return newDatas
}

type ChCustomServiceDevice struct {
	SubscriberComponent[
		*message.AddedCustomServices,
		message.AddedCustomServices,
		*message.UpdatedCustomService,
		message.UpdatedCustomService,
		*message.DeletedCustomServices,
		message.DeletedCustomServices,
		metadbmodel.CustomService,
		metadbmodel.ChDevice,
		DeviceKey,
	]
	resourceTypeToIconID map[IconKey]int
}

func NewChCustomServiceDevice(resourceTypeToIconID map[IconKey]int) *ChCustomServiceDevice {
	mng := &ChCustomServiceDevice{
		newSubscriberComponent[
			*message.AddedCustomServices,
			message.AddedCustomServices,
			*message.UpdatedCustomService,
			message.UpdatedCustomService,
			*message.DeletedCustomServices,
			message.DeletedCustomServices,
			metadbmodel.CustomService,
			metadbmodel.ChDevice,
			DeviceKey,
		](
			common.RESOURCE_TYPE_CUSTOM_SERVICE_EN, RESOURCE_TYPE_CH_DEVICE,
		),
		resourceTypeToIconID,
	}
	mng.setSubscribeRecorder(false)
	mng.subscriberDG = mng
	return mng
}

// sourceToTarget implements SubscriberDataGenerator
func (c *ChCustomServiceDevice) sourceToTarget(md *message.Metadata, source *metadbmodel.CustomService) (keys []DeviceKey, targets []metadbmodel.ChDevice) {
	iconID := c.resourceTypeToIconID[IconKey{
		NodeType: RESOURCE_TYPE_CUSTOM_SERVICE,
	}]
	sourceName := source.Name
	keys = append(keys, DeviceKey{DeviceType: CH_DEVICE_TYPE_CUSTOM_SERVICE,
		DeviceID: source.ID})
	targets = append(targets, metadbmodel.ChDevice{
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
func (c *ChCustomServiceDevice) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedCustomService) {
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChCustomServiceDevice) softDeletedTargetsUpdated(targets []metadbmodel.ChDevice, db *metadb.DB) {
}
