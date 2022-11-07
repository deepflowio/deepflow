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

package eventapi

import "github.com/deepflowys/deepflow/server/libs/pool"

const (
	RESOURCE_EVENT_TYPE_CREATE       = "create"
	RESOURCE_EVENT_TYPE_DELETE       = "delete"
	RESOURCE_EVENT_TYPE_UPDATE_STATE = "update-state"
	RESOURCE_EVENT_TYPE_MIGRATE      = "migrate"
	RESOURCE_EVENT_TYPE_RECREATE     = "recreate"
	RESOURCE_EVENT_TYPE_ADD_IP       = "add-ip"
	RESOURCE_EVENT_TYPE_REMOVE_IP    = "remove-ip"
)

type ResourceEvent struct {
	Time         int64
	Type         string
	InstanceType uint32 // the value is the same as l3_device_type
	InstanceID   uint32
	InstanceName string
	SubnetIDs    []uint32
	IPs          []string
	Description  string

	IfNeedTagged bool // if need ingester set tag
	RegionID     uint32
	AZID         uint32
	VPCID        uint32
	L3DeviceType uint32
	L3DeviceID   uint32
	HostID       uint32
	PodClusterID uint32
	PodNSID      uint32
	PodNodeID    uint32
	PodServiceID uint32
	PodGroupID   uint32
	PodID        uint32
}

type ResourceOption func(opts *ResourceEvent)

func SubnetIDs(netIDs []uint32) ResourceOption {
	return func(r *ResourceEvent) {
		r.SubnetIDs = netIDs
	}
}

func IPs(ips []string) ResourceOption {
	return func(r *ResourceEvent) {
		r.IPs = ips
	}
}

func Description(description string) ResourceOption {
	return func(r *ResourceEvent) {
		r.Description = description
	}
}

func RegionID(id int) ResourceOption {
	return func(r *ResourceEvent) {
		r.RegionID = uint32(id)
	}
}

func AZID(id int) ResourceOption {
	return func(r *ResourceEvent) {
		r.AZID = uint32(id)
	}
}

func VPCID(id int) ResourceOption {
	return func(r *ResourceEvent) {
		r.VPCID = uint32(id)
	}
}

func L3DeviceType(id int) ResourceOption {
	return func(r *ResourceEvent) {
		r.L3DeviceType = uint32(id)
	}
}

func L3DeviceID(id int) ResourceOption {
	return func(r *ResourceEvent) {
		r.L3DeviceID = uint32(id)
	}
}

func HostID(id int) ResourceOption {
	return func(r *ResourceEvent) {
		r.HostID = uint32(id)
	}
}

func PodClusterID(id int) ResourceOption {
	return func(r *ResourceEvent) {
		r.PodClusterID = uint32(id)
	}
}

func PodNSID(id int) ResourceOption {
	return func(r *ResourceEvent) {
		r.PodNSID = uint32(id)
	}
}

func PodNodeID(id int) ResourceOption {
	return func(r *ResourceEvent) {
		r.PodNodeID = uint32(id)
	}
}

func PodServiceID(id int) ResourceOption {
	return func(r *ResourceEvent) {
		r.PodServiceID = uint32(id)
	}
}

func PodGroupID(id int) ResourceOption {
	return func(r *ResourceEvent) {
		r.PodGroupID = uint32(id)
	}
}

func PodID(id int) ResourceOption {
	return func(r *ResourceEvent) {
		r.PodID = uint32(id)
	}
}

func (r *ResourceEvent) Release() {
	ReleaseResourceEvent(r)
}

var poolResourceEvent = pool.NewLockFreePool(func() interface{} {
	return new(ResourceEvent)
})

func AcquireResourceEvent() *ResourceEvent {
	return poolResourceEvent.Get().(*ResourceEvent)
}

func ReleaseResourceEvent(event *ResourceEvent) {
	if event == nil {
		return
	}
	*event = ResourceEvent{}
	poolResourceEvent.Put(event)
}
