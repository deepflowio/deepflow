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

package event

import (
	"reflect"
	"testing"

	"github.com/deepflowio/deepflow/server/libs/eventapi"
)

func TestEventManagerBase_convertToEventBeEnqueued(t *testing.T) {
	type args struct {
		ev *eventapi.ResourceEvent
	}
	tests := []struct {
		name string
		args args
		want *eventapi.ResourceEvent
	}{
		{
			name: "empty field",
			args: args{
				ev: &eventapi.ResourceEvent{},
			},
			want: &eventapi.ResourceEvent{},
		},
		{
			name: "nil param",
			args: args{
				ev: nil,
			},
			want: &eventapi.ResourceEvent{},
		},
		{
			name: "all fields",
			args: args{
				ev: &eventapi.ResourceEvent{
					Time:               1257894000,
					TimeMilli:          1257894000000,
					Type:               eventapi.RESOURCE_EVENT_TYPE_CREATE,
					InstanceType:       10,
					InstanceID:         29024,
					InstanceName:       "slave-deepflow-ck",
					AttributeSubnetIDs: []uint32{7158},
					AttributeIPs:       []string{"127.0.0.1"},
					Description:        "description...",
					GProcessID:         0,
					GProcessName:       "",

					IfNeedTagged: true,
					RegionID:     0,
					AZID:         0,
					VPCID:        0,
					L3DeviceType: 1,
					L3DeviceID:   2,
					HostID:       3,
					PodClusterID: 4,
					PodNSID:      5,
					PodNodeID:    6,
					PodServiceID: 7,
					PodGroupID:   8,
					PodID:        9,
					SubnetID:     7158,
					IP:           "127.0.0.1",
				},
			},
			want: &eventapi.ResourceEvent{
				Time:               1257894000,
				TimeMilli:          1257894000000,
				Type:               eventapi.RESOURCE_EVENT_TYPE_CREATE,
				InstanceType:       10,
				InstanceID:         29024,
				InstanceName:       "slave-deepflow-ck",
				AttributeSubnetIDs: []uint32{7158},
				AttributeIPs:       []string{"127.0.0.1"},
				Description:        "description...",
				GProcessID:         0,
				GProcessName:       "",

				IfNeedTagged: true,
				RegionID:     0,
				AZID:         0,
				VPCID:        0,
				L3DeviceType: 1,
				L3DeviceID:   2,
				HostID:       3,
				PodClusterID: 4,
				PodNSID:      5,
				PodNodeID:    6,
				PodServiceID: 7,
				PodGroupID:   8,
				PodID:        9,
				SubnetID:     7158,
				IP:           "127.0.0.1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &EventManagerBase{}
			if got := e.convertToEventBeEnqueued(tt.args.ev); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EventManagerBase.convertToEventBeEnqueued() = %v, want %v", got, tt.want)
			}
		})
	}
}
