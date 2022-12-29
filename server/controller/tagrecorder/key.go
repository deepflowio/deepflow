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

package tagrecorder

type IDKey struct {
	ID int
}

type DeviceKey struct {
	DeviceID   int
	DeviceType int
}

type IPResourceKey struct {
	IP       string
	SubnetID int
}

type PortIDKey struct {
	ID       int
	Protocol int
	Port     int
}

type PortIPKey struct {
	IP       string
	SubnetID int
	Protocol int
	Port     int
}

type PortDeviceKey struct {
	DeviceID   int
	DeviceType int
	Protocol   int
	Port       int
}

type VtapPortKey struct {
	VtapID  int
	TapPort int64
}

type IPRelationKey struct {
	VPCID int
	IP    string
}

type K8sLabelKey struct {
	PodID int
	Key   string
}

type K8sLabelsKey struct {
	PodID int
}

type TapTypeKey struct {
	Value int
}

type StringEnumTagKey struct {
	TagName  string
	TagValue string
}

type IntEnumTagKey struct {
	TagName  string
	TagValue int
}

type NodeTypeKey struct {
	ResourceType int
}

type CloudTagKey struct {
	ID  int
	Key string
}

type CloudTagsKey struct {
	ID int
}

type OSAPPTagKey struct {
	PID int
	Key string
}

type OSAPPTagsKey struct {
	PID int
}
