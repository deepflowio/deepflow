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

package event

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
	ResourceType uint32 // the value is the same as l3_device_type
	ResourceID   uint32
	ResourceName string
	Description  string
}
