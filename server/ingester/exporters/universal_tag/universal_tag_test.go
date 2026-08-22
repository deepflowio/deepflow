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

package universal_tag

import (
	"testing"
)

// Every device type common.GetAutoService can return has to resolve to a
// non-empty string, because the exporter serializes auto_service_type from this
// table and an empty value drops the tag out of the exported JSON entirely.
// The pod_group subtypes and pod_cluster used to be missing, which silently
// removed auto_service_type from every pod endpoint with no pod_service in
// front of it and from every pod_node endpoint.
func TestDeviceTypeStringCoversAutoServiceTypes(t *testing.T) {
	// Mirrors flow_tag.node_type_map (tagrecorder's RESOURCE_TYPE_TO_NODE_TYPE).
	for _, tt := range []struct {
		deviceType DeviceType
		want       string
	}{
		{TYPE_CUSTOM_SERVICE, "custom_service"},
		{TYPE_POD_SERVICE, "pod_service"},
		{TYPE_POD_GROUP, "pod_group"},
		{TYPE_POD_GROUP_DEPLOYMENT, "pod_group"},
		{TYPE_POD_GROUP_STATEFULSET, "pod_group"},
		{TYPE_POD_GROUP_RC, "pod_group"},
		{TYPE_POD_GROUP_DAEMON_SET, "pod_group"},
		{TYPE_POD_GROUP_REPLICASET_CONTROLLER, "pod_group"},
		{TYPE_POD_GROUP_CLONESET, "pod_group"},
		{TYPE_GPROCESS, "gprocess"},
		{TYPE_POD_CLUSTER, "pod_cluster"},
		{TYPE_VM, "chost"},
		{TYPE_POD, "pod"},
		{TYPE_POD_NODE, "pod_node"},
		{TYPE_LB, "lb"},
		{TYPE_NAT_GATEWAY, "natgw"},
		{TYPE_RDS_INSTANCE, "rds"},
		{TYPE_REDIS_INSTANCE, "redis"},
		{TYPE_INTERNET, "internet_ip"},
		{TYPE_IP, "ip"},
	} {
		if got := tt.deviceType.String(); got != tt.want {
			t.Errorf("DeviceType(%d).String() = %q, want %q", tt.deviceType, got, tt.want)
		}
	}
}

// makeManagerWithPodGroup builds a manager whose org=1 device map holds one
// pod_group, keyed by the controller subtype the platform data uses. Built
// in-package so the test does not go through the production constructor, which
// starts a gRPC session and registers debug handlers.
func makeManagerWithPodGroup(deviceType DeviceType, deviceID uint32, name string) *UniversalTagsManager {
	u := &UniversalTagsManager{}
	u.universalTagMaps[1] = &UniversalTagMaps{
		deviceMap: map[uint64]string{
			uint64(deviceType)<<32 | uint64(deviceID): name,
		},
		regionMap:     map[uint16]string{},
		azMap:         map[uint16]string{},
		podNodeMap:    map[uint32]string{},
		podNsMap:      map[uint16]string{},
		podGroupMap:   map[uint32]string{},
		podMap:        map[uint32]string{},
		podClusterMap: map[uint16]string{},
		l3EpcMap:      map[uint32]string{},
		subnetMap:     map[uint16]string{},
		gprocessMap:   map[uint32]string{},
		vtapMap:       map[uint16]string{},
	}
	return u
}

// A pod with no pod_service in front of it: GetAutoService returns the workload
// controller's own subtype (134, a ReplicaSet controller), so auto_service_type
// has to come out as "pod_group" while the name still resolves from the device
// map keyed by that same subtype. Before the table was completed, the name
// resolved and the type came out empty.
func TestQueryUniversalTagsPodGroupAutoServiceType(t *testing.T) {
	u := makeManagerWithPodGroup(TYPE_POD_GROUP_REPLICASET_CONTROLLER, 777, "some-workload")
	tags := u.QueryUniversalTags(
		1,                   // orgId
		0, 0, 0, 0, 0, 0, 0, // regionID, azID, hostID, podNsID, podClusterID, subnetID, agentID
		uint8(TYPE_VM), // l3DeviceType (the chost the pod sits on)
		uint8(TYPE_POD_GROUP_REPLICASET_CONTROLLER), // autoServiceType
		uint8(TYPE_POD),  // autoInstanceType
		0,                // l3DeviceID
		777,              // autoServiceID
		0,                // autoInstanceID
		0, 0, 0, 0, 0, 0, // podNodeID, podGroupID, podID, l3EpcID, gprocessID, serviceID
		true, 0, nil,
	)
	if tags[AutoServiceType] != "pod_group" {
		t.Errorf("pod_group auto_service_type = %q, want \"pod_group\"", tags[AutoServiceType])
	}
	if tags[AutoService] != "some-workload" {
		t.Errorf("pod_group auto_service = %q, want \"some-workload\"", tags[AutoService])
	}
}

// pod_node endpoints land on PodClusterType (103) via GetAutoService's
// podClusterID branch, which was the other hole in the table.
func TestQueryUniversalTagsPodClusterAutoServiceType(t *testing.T) {
	u := makeManagerWithPodGroup(TYPE_POD_CLUSTER, 42, "some-cluster")
	tags := u.QueryUniversalTags(
		1,
		0, 0, 0, 0, 0, 0, 0,
		uint8(TYPE_VM),
		uint8(TYPE_POD_CLUSTER), // autoServiceType
		uint8(TYPE_POD_NODE),    // autoInstanceType
		0,
		42, // autoServiceID
		0,
		0, 0, 0, 0, 0, 0,
		true, 0, nil,
	)
	if tags[AutoServiceType] != "pod_cluster" {
		t.Errorf("pod_node auto_service_type = %q, want \"pod_cluster\"", tags[AutoServiceType])
	}
}
