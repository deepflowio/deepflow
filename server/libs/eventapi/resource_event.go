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

package eventapi

import "github.com/deepflowio/deepflow/server/libs/pool"

const (
	RESOURCE_EVENT_TYPE_CREATE            = "create"
	RESOURCE_EVENT_TYPE_DELETE            = "delete"
	RESOURCE_EVENT_TYPE_UPDATE_STATE      = "update-state"
	RESOURCE_EVENT_TYPE_MIGRATE           = "migrate"
	RESOURCE_EVENT_TYPE_RECREATE          = "recreate"
	RESOURCE_EVENT_TYPE_ATTACH_IP         = "attach-ip"
	RESOURCE_EVENT_TYPE_DETACH_IP         = "detach-ip"
	RESOURCE_EVENT_TYPE_MODIFY            = "modify"
	RESOURCE_EVENT_TYPE_ATTACH_CONFIG_MAP = "attach-config"
	RESOURCE_EVENT_TYPE_MODIFY_CONFIG_MAP = "modify-config"
	RESOURCE_EVENT_TYPE_DETACH_CONFIG_MAP = "detach-config"
)

type ResourceEvent struct {
	Time               int64
	TimeMilli          int64 // record millisecond time for debug
	Type               string
	InstanceType       uint32 // the value is the same as l3_device_type
	InstanceID         uint32
	InstanceName       string
	AttributeSubnetIDs []uint32
	AttributeIPs       []string
	Description        string

	IfNeedTagged bool // if need ingester set tag
	GProcessID   uint32
	GProcessName string
	RegionID     uint32
	AZID         uint32
	VPCID        uint32
	L3DeviceType uint32
	L3DeviceID   uint32
	HostID       uint32
	PodClusterID uint32
	PodNSID      uint32
	PodNodeID    uint32
	PodServiceID uint32 // TODO 此字段在 ingester 中并未被使用，待删除
	PodGroupID   uint32
	PodGroupType uint8
	PodID        uint32
	SubnetID     uint32
	IP           string
	ConfigMapID  uint32

	AttributeNames  []string
	AttributeValues []string

	ORGID  uint16
	TeamID uint16
}

const (
	AttributeNameConfigName = "config_name"
	AttributeNameConfig     = "config"
	AttributeNameConfigDiff = "config_diff"
)

type TagFieldOption func(opts *ResourceEvent)

func TagConfigMapID(id uint32) TagFieldOption {
	return func(r *ResourceEvent) {
		r.ConfigMapID = id
	}
}

func TagAttributes(names, values []string) TagFieldOption {
	return func(r *ResourceEvent) {
		r.AttributeNames = names
		r.AttributeValues = values
	}
}

func TagInstanceType(instanceType uint32) TagFieldOption {
	return func(r *ResourceEvent) {
		r.InstanceType = instanceType
	}
}

func TagInstanceID(instanceID uint32) TagFieldOption {
	return func(r *ResourceEvent) {
		r.InstanceID = instanceID
	}
}

func TagInstanceName(instanceName string) TagFieldOption {
	return func(r *ResourceEvent) {
		r.InstanceName = instanceName
	}
}

func TagAttributeSubnetIDs(netIDs []uint32) TagFieldOption {
	return func(r *ResourceEvent) {
		r.AttributeSubnetIDs = netIDs
	}
}

func TagAttributeIPs(ips []string) TagFieldOption {
	return func(r *ResourceEvent) {
		r.AttributeIPs = ips
	}
}

func TagDescription(description string) TagFieldOption {
	return func(r *ResourceEvent) {
		r.Description = description
	}
}

func TagRegionID(id int) TagFieldOption {
	return func(r *ResourceEvent) {
		r.RegionID = uint32(id)
	}
}

func TagAZID(id int) TagFieldOption {
	return func(r *ResourceEvent) {
		r.AZID = uint32(id)
	}
}

func TagVPCID(id int) TagFieldOption {
	return func(r *ResourceEvent) {
		r.VPCID = uint32(id)
	}
}

func TagL3DeviceType(id int) TagFieldOption {
	return func(r *ResourceEvent) {
		r.L3DeviceType = uint32(id)
	}
}

func TagL3DeviceID(id int) TagFieldOption {
	return func(r *ResourceEvent) {
		r.L3DeviceID = uint32(id)
	}
}

func TagHostID(id int) TagFieldOption {
	return func(r *ResourceEvent) {
		r.HostID = uint32(id)
	}
}

func TagPodClusterID(id int) TagFieldOption {
	return func(r *ResourceEvent) {
		r.PodClusterID = uint32(id)
	}
}

func TagPodNSID(id int) TagFieldOption {
	return func(r *ResourceEvent) {
		r.PodNSID = uint32(id)
	}
}

func TagPodNodeID(id int) TagFieldOption {
	return func(r *ResourceEvent) {
		r.PodNodeID = uint32(id)
	}
}

func TagPodServiceID(id int) TagFieldOption {
	return func(r *ResourceEvent) {
		r.PodServiceID = uint32(id) // TODO 此字段在 ingester 中并未被使用，待删除
	}
}

func TagPodGroupID(id int) TagFieldOption {
	return func(r *ResourceEvent) {
		r.PodGroupID = uint32(id)
	}
}

func TagPodGroupType(t uint32) TagFieldOption {
	return func(r *ResourceEvent) {
		r.PodGroupType = uint8(t)
	}
}

func TagPodID(id int) TagFieldOption {
	return func(r *ResourceEvent) {
		r.PodID = uint32(id)
	}
}

func TagSubnetID(id uint32) TagFieldOption {
	return func(r *ResourceEvent) {
		r.SubnetID = uint32(id)
	}
}

func TagIP(ip string) TagFieldOption {
	return func(r *ResourceEvent) {
		r.IP = ip
	}
}

func TagGProcessID(id uint32) TagFieldOption {
	return func(r *ResourceEvent) {
		r.GProcessID = id
	}
}

func TagGProcessName(name string) TagFieldOption {
	return func(r *ResourceEvent) {
		r.GProcessName = name
	}
}

func (r *ResourceEvent) Release() {
	ReleaseResourceEvent(r)
}

var poolResourceEvent = pool.NewLockFreePool(func() *ResourceEvent {
	return new(ResourceEvent)
})

func AcquireResourceEvent() *ResourceEvent {
	return poolResourceEvent.Get()
}

func ReleaseResourceEvent(event *ResourceEvent) {
	if event == nil {
		return
	}
	*event = ResourceEvent{}
	poolResourceEvent.Put(event)
}
