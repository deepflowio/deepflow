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

import (
	"fmt"
	"testing"

	cloudmodel "github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	"github.com/deepflowys/deepflow/server/libs/eventapi"
	"github.com/stretchr/testify/assert"
)

func TestVM_ProduceByAdd(t *testing.T) {
	type args struct {
		items []*mysql.VM
	}
	tests := []struct {
		name      string
		v         *VM
		args      args
		wantID    uint32
		wantName  string
		wantVPCID uint32
	}{
		{
			name: "add success",
			v:    NewVM(&cache.ToolDataSet{}, NewEventQueue()),
			args: args{
				items: []*mysql.VM{
					{
						Base:  mysql.Base{ID: 1},
						Name:  "vm",
						VPCID: 2,
					},
				},
			},
			wantID:    1,
			wantName:  "vm",
			wantVPCID: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.v.ProduceByAdd(tt.args.items)

			e := tt.v.EventManager.Queue.Get().(*eventapi.ResourceEvent)
			assert.Equal(t, tt.wantID, e.InstanceID)
			assert.Equal(t, tt.wantName, e.InstanceName)
			assert.Equal(t, tt.wantVPCID, e.VPCID)
		})

	}
}

func TestVM_ProduceByDelete(t *testing.T) {
	type args struct {
		lcuuids []string
	}
	tests := []struct {
		name     string
		dataSet  *cache.ToolDataSet
		v        *VM
		args     args
		wantID   uint32
		wantName string
	}{
		{
			name: "delete success",
			dataSet: &cache.ToolDataSet{
				VMLcuuidToID: map[string]int{
					"ff6f9b99-82ef-5507-b6b6-cbab28bda9cb": 1,
				},
				EventToolDataSet: cache.EventToolDataSet{
					VMIDToName: map[int]string{
						1: "vm_name",
					},
				},
			},
			args: args{
				lcuuids: []string{"ff6f9b99-82ef-5507-b6b6-cbab28bda9cb"},
			},
			wantID:   1,
			wantName: "vm_name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.v = NewVM(tt.dataSet, NewEventQueue())
			tt.v.ProduceByDelete(tt.args.lcuuids)

			e := tt.v.EventManager.Queue.Get().(*eventapi.ResourceEvent)
			assert.Equal(t, tt.wantID, e.InstanceID)
			assert.Equal(t, tt.wantName, e.InstanceName)
		})
	}
}

func TestVM_ProduceByUpdate(t *testing.T) {
	type args struct {
		cloudItem *cloudmodel.VM
		diffBase  *cache.VM
	}
	tests := []struct {
		name            string
		dataSet         cache.ToolDataSet
		v               *VM
		args            args
		wantID          uint32
		wantName        string
		wantDescription string
	}{
		{
			name: "migrate success",
			dataSet: cache.ToolDataSet{
				VMLcuuidToID: map[string]int{
					"ff6f9b99-82ef-5507-b6b6-cbab28bda9cb": 1,
				},
				EventToolDataSet: cache.EventToolDataSet{
					VMIDToName: map[int]string{
						1: "vm_name",
					},
				},
			},
			args: args{
				diffBase: &cache.VM{
					LaunchServer: "10.50.1.13",
				},
				cloudItem: &cloudmodel.VM{
					Lcuuid:       "ff6f9b99-82ef-5507-b6b6-cbab28bda9cb",
					LaunchServer: "10.50.1.14",
				},
			},
			wantID:          1,
			wantName:        "vm_name",
			wantDescription: "10.50.1.13,10.50.1.14",
		},
		{
			name: "update state success",
			dataSet: cache.ToolDataSet{
				VMLcuuidToID: map[string]int{
					"ff6f9b99-82ef-5507-b6b6-cbab28bda9cb": 1,
				},
				EventToolDataSet: cache.EventToolDataSet{
					VMIDToName: map[int]string{
						1: "vm_name",
					},
				},
			},
			args: args{
				diffBase: &cache.VM{
					State: common.VM_STATE_EXCEPTION,
				},
				cloudItem: &cloudmodel.VM{
					Lcuuid: "ff6f9b99-82ef-5507-b6b6-cbab28bda9cb",
					State:  common.VM_STATE_RUNNING,
				},
			},
			wantID:          1,
			wantName:        "vm_name",
			wantDescription: fmt.Sprintf("%s,%s", VMStateToString[common.VM_STATE_EXCEPTION], VMStateToString[common.VM_STATE_RUNNING]),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.v = NewVM(&tt.dataSet, NewEventQueue())
			tt.v.ProduceByUpdate(tt.args.cloudItem, tt.args.diffBase)

			e := tt.v.EventManager.Queue.Get().(*eventapi.ResourceEvent)
			assert.Equal(t, tt.wantID, e.InstanceID)
			assert.Equal(t, tt.wantName, e.InstanceName)
			assert.Equal(t, tt.wantDescription, e.Description)
		})
	}
}
