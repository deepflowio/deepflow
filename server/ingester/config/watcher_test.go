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

package config

import (
	"reflect"
	"testing"
)

func TestGetServerEndpointMapNormal(t *testing.T) {
	nodePodNamesMap := map[string][]string{
		"node1": {"pod1"},
		"node2": {"pod2"},
		"node3": {"pod3"},
	}
	nodeEndpointsMap := map[string][]Endpoint{
		"node1": {{"1.1.1.1", 9000}},
		"node2": {{"1.1.1.2", 9000}},
		"node3": {{"1.1.1.3", 9000}},
	}

	expect := map[string][]Endpoint{
		"node1pod1": {{"1.1.1.1", 9000}},
		"node2pod2": {{"1.1.1.2", 9000}},
		"node3pod3": {{"1.1.1.3", 9000}},
	}
	actual := getServerEndpointMap(nodePodNamesMap, nodeEndpointsMap)
	if !serverEndpointMapEqual(expect, actual) {
		t.Errorf("Expected %v found %v", expect, actual)
	}
}

func TestGetServerEndpointMap2(t *testing.T) {
	nodePodNamesMap := map[string][]string{
		"node1": {"pod11", "pod12"},
		"node2": {"pod21", "pod22"},
	}
	nodeEndpointsMap := map[string][]Endpoint{
		"node1": {{"1.1.1.1", 9000}},
		"node2": {{"1.1.1.2", 9000}},
	}

	expect := map[string][]Endpoint{
		"node1pod11": {{"1.1.1.1", 9000}},
		"node1pod12": {{"1.1.1.1", 9000}},
		"node2pod21": {{"1.1.1.2", 9000}},
		"node2pod22": {{"1.1.1.2", 9000}},
	}
	actual := getServerEndpointMap(nodePodNamesMap, nodeEndpointsMap)
	if !serverEndpointMapEqual(expect, actual) {
		t.Errorf("Expected %v found %v", expect, actual)
	}
}

func TestGetServerEndpointMap3(t *testing.T) {
	nodePodNamesMap := map[string][]string{
		"node1": {"pod11", "pod12"},
		"node2": {"pod21", "pod22"},
	}
	nodeEndpointsMap := map[string][]Endpoint{
		"node1": {{"1.1.1.11", 9000}, {"1.1.1.12", 9000}},
		"node2": {{"1.1.1.21", 9000}, {"1.1.1.22", 9000}},
	}

	expect := map[string][]Endpoint{
		"node1pod11": {{"1.1.1.11", 9000}},
		"node1pod12": {{"1.1.1.12", 9000}},
		"node2pod21": {{"1.1.1.21", 9000}},
		"node2pod22": {{"1.1.1.22", 9000}},
	}
	actual := getServerEndpointMap(nodePodNamesMap, nodeEndpointsMap)
	if !serverEndpointMapEqual(expect, actual) {
		t.Errorf("Expected %v found %v", expect, actual)
	}
}

func TestGetServerEndpointMap4(t *testing.T) {
	nodePodNamesMap := map[string][]string{
		"node1": {"pod11"},
		"node2": {"pod21", "pod22"},
	}
	nodeEndpointsMap := map[string][]Endpoint{
		"node1": {{"1.1.1.11", 9000}, {"1.1.1.12", 9000}},
		"node2": {{"1.1.1.21", 9000}},
	}

	expect := map[string][]Endpoint{
		"node1pod11": {{"1.1.1.11", 9000}, {"1.1.1.12", 9000}},
		"node2pod21": {{"1.1.1.21", 9000}},
		"node2pod22": {{"1.1.1.21", 9000}},
	}
	actual := getServerEndpointMap(nodePodNamesMap, nodeEndpointsMap)
	if !serverEndpointMapEqual(expect, actual) {
		t.Errorf("Expected %v found %v", expect, actual)
	}
}

func TestGetServerEndpointMapExternal(t *testing.T) {
	nodeNames := []string{"pod1", "pod2", "pod3"}
	endpoints := []Endpoint{{"1.1.1.11", 9000}, {"1.1.1.12", 9000}, {"1.1.1.13", 9000}, {"1.1.1.14", 9000}, {"1.1.1.15", 9000}}

	myName := "pod1"
	expect := []Endpoint{{"1.1.1.11", 9000}, {"1.1.1.14", 9000}}
	actual, _ := getMyClickhouseEndpoints(nodeNames, myName, endpoints)
	if !reflect.DeepEqual(expect, actual) {
		t.Errorf("Expected %v found %v", expect, actual)
	}

	myName = "pod2"
	expect = []Endpoint{{"1.1.1.12", 9000}, {"1.1.1.15", 9000}}
	actual, _ = getMyClickhouseEndpoints(nodeNames, myName, endpoints)
	if !reflect.DeepEqual(expect, actual) {
		t.Errorf("Expected %v found %v", expect, actual)
	}

	myName = "pod3"
	expect = []Endpoint{{"1.1.1.13", 9000}}
	actual, _ = getMyClickhouseEndpoints(nodeNames, myName, endpoints)
	if !reflect.DeepEqual(expect, actual) {
		t.Errorf("Expected %v found %v", expect, actual)
	}
}
