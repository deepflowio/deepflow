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

type DeviceKey struct {
	DeviceID   int `json:"deviceid"`
	DeviceType int `json:"devicetype"`
}

func (k DeviceKey) Map() map[string]interface{} {
	return map[string]interface{}{
		"deviceid":   k.DeviceID,
		"devicetype": k.DeviceType,
	}
}

type IDKey struct {
	ID int `json:"id"`
}

func (k IDKey) Map() map[string]interface{} {
	return map[string]interface{}{
		"id": k.ID,
	}
}

func NewIDKeyKey(id int, key string) IDKeyKey {
	return IDKeyKey{
		ID:  id,
		Key: key,
	}
}

type IDKeyKey struct {
	ID  int    `json:"id"`
	Key string `json:"key"`
}

func (k IDKeyKey) Map() map[string]interface{} {
	return map[string]interface{}{
		"id":    k.ID,
		"`key`": k.Key,
	}
}

type OSAPPTagKey struct {
	PID int    `json:"pid"`
	Key string `json:"key"`
}

func (k OSAPPTagKey) Map() map[string]interface{} {
	return map[string]interface{}{
		"pid":   k.PID,
		"`key`": k.Key,
	}
}

type OSAPPTagsKey struct {
	PID int `json:"pid"`
}

func (k OSAPPTagsKey) Map() map[string]interface{} {
	return map[string]interface{}{
		"pid": k.PID,
	}
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
	L3EPCID int
	IP      string
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

type PrometheusAPPLabelKey struct {
	LabelNameID  int
	LabelValueID int
}

type PrometheusTargetLabelKey struct {
	MetricID    int
	LabelNameID int
	TargetID    int
}

type PolicyKey struct {
	ACLGID     int
	TunnelType int
}
