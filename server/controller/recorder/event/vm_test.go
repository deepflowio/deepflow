/*
 * Copyright (c) 2023 Yunshan Networks
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

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/stretchr/testify/assert"
)

func TestVM_ProduceByAdd(t *testing.T) {
	type args struct {
		items []*mysql.VM
	}
	tests := []struct {
		name      string
		cache     *cache.Cache
		v         *VM
		args      args
		prepare   func(*cache.Cache)
		wantID    uint32
		wantName  string
		wantVPCID uint32
	}{
		{
			name: "add success",
			args: args{
				items: []*mysql.VM{
					{
						Base:  mysql.Base{ID: 1},
						Name:  "vm_name",
						VPCID: 3,
					},
				},
			},
			prepare: func(cache *cache.Cache) {
				cache.AddRegion(&mysql.Region{Base: mysql.Base{ID: 1, Lcuuid: "region_lcuuid"}})
				cache.AddAZ(&mysql.AZ{Base: mysql.Base{ID: 2, Lcuuid: "az_lcuuid"}})
				cache.AddVPCs([]*mysql.VPC{{Base: mysql.Base{ID: 3, Lcuuid: "vpc_lcuuid"}}})
				cache.AddHost(&mysql.Host{
					Base:   mysql.Base{ID: 4, Lcuuid: "host_lcuuid"},
					IP:     "10.233.101.79",
					Region: "region_lcuuid",
					AZ:     "az_lcuuid",
				})
				cache.AddVM(&mysql.VM{
					Base: mysql.Base{
						ID:     1,
						Lcuuid: "vm_lcuuid",
					},
					Name:         "vm_name",
					Region:       "region_lcuuid",
					AZ:           "az_lcuuid",
					VPCID:        3,
					LaunchServer: "10.233.101.79",
				})
			},
			wantID:    1,
			wantName:  "vm_name",
			wantVPCID: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cache = &cache.Cache{
				DiffBaseDataSet: diffbase.NewDataSet(),
				ToolDataSet:     tool.NewDataSet(),
			}
			tt.prepare(tt.cache)
			tt.v = NewVM(tt.cache.ToolDataSet, NewEventQueue())
			tt.v.ProduceByAdd(tt.args.items)

			e := tt.v.EventManagerBase.Queue.Get().(*eventapi.ResourceEvent)
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
		cache    *cache.Cache
		v        *VM
		args     args
		prepare  func(*cache.Cache)
		wantID   uint32
		wantName string
	}{
		{
			name: "delete success",
			cache: &cache.Cache{
				DiffBaseDataSet: diffbase.NewDataSet(),
				ToolDataSet:     tool.NewDataSet(),
			},
			args: args{
				lcuuids: []string{"vm_lcuuid"},
			},
			prepare: func(cache *cache.Cache) {
				cache.AddRegion(&mysql.Region{Base: mysql.Base{ID: 1, Lcuuid: "region_lcuuid"}})
				cache.AddAZ(&mysql.AZ{Base: mysql.Base{ID: 2, Lcuuid: "az_lcuuid"}})
				cache.AddVPCs([]*mysql.VPC{{Base: mysql.Base{ID: 3, Lcuuid: "vpc_lcuuid"}}})
				cache.AddHost(&mysql.Host{
					Base:   mysql.Base{ID: 4, Lcuuid: "host_lcuuid"},
					IP:     "10.233.101.79",
					Region: "region_lcuuid",
					AZ:     "az_lcuuid",
				})
				cache.AddVM(&mysql.VM{
					Base: mysql.Base{
						ID:     1,
						Lcuuid: "vm_lcuuid",
					},
					Name:         "vm_name",
					Region:       "region_lcuuid",
					AZ:           "az_lcuuid",
					VPCID:        3,
					LaunchServer: "10.233.101.79",
				})
			},
			wantID:   1,
			wantName: "vm_name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepare(tt.cache)
			tt.v = NewVM(tt.cache.ToolDataSet, NewEventQueue())
			tt.v.ProduceByDelete(tt.args.lcuuids)

			e := tt.v.EventManagerBase.Queue.Get().(*eventapi.ResourceEvent)
			assert.Equal(t, tt.wantID, e.InstanceID)
			assert.Equal(t, tt.wantName, e.InstanceName)
		})
	}
}

func TestVM_ProduceByUpdate(t *testing.T) {
	type args struct {
		cloudItem *cloudmodel.VM
		diffBase  *diffbase.VM
	}
	tests := []struct {
		name      string
		cache     *cache.Cache
		v         *VM
		args      args
		prepare   func(*cache.Cache)
		assertion func(*testing.T, *eventapi.ResourceEvent)
	}{
		{
			name: "migrate success",
			args: args{
				diffBase: &diffbase.VM{
					LaunchServer: "10.50.1.13",
				},
				cloudItem: &cloudmodel.VM{
					Lcuuid:       "vm_lcuuid",
					LaunchServer: "10.50.1.14",
				},
			},
			prepare: func(cache *cache.Cache) {
				cache.AddRegion(&mysql.Region{Base: mysql.Base{ID: 1, Lcuuid: "region_lcuuid"}})
				cache.AddAZ(&mysql.AZ{Base: mysql.Base{ID: 2, Lcuuid: "az_lcuuid"}})
				cache.AddVPCs([]*mysql.VPC{{Base: mysql.Base{ID: 3, Lcuuid: "vpc_lcuuid"}}})
				cache.AddHost(&mysql.Host{
					Base:   mysql.Base{ID: 4, Lcuuid: "host_lcuuid"},
					IP:     "10.233.101.79",
					Region: "region_lcuuid",
					AZ:     "az_lcuuid",
				})
				cache.AddVM(&mysql.VM{
					Base: mysql.Base{
						ID:     1,
						Lcuuid: "vm_lcuuid",
					},
					Name:         "vm_name",
					Region:       "region_lcuuid",
					AZ:           "az_lcuuid",
					VPCID:        3,
					LaunchServer: "10.233.101.79",
				})
			},
			assertion: func(t *testing.T, e *eventapi.ResourceEvent) {
				assert.Equal(t, uint32(1), e.InstanceID)
				assert.Equal(t, "vm_name", e.InstanceName)
				assert.Equal(t, "10.50.1.13,10.50.1.14", e.Description)
			},
		},
		{
			name: "update state success",
			args: args{
				diffBase: &diffbase.VM{
					State: common.VM_STATE_EXCEPTION,
				},
				cloudItem: &cloudmodel.VM{
					Lcuuid: "vm_lcuuid",
					State:  common.VM_STATE_RUNNING,
				},
			},
			prepare: func(cache *cache.Cache) {
				cache.AddRegion(&mysql.Region{Base: mysql.Base{ID: 1, Lcuuid: "region_lcuuid"}})
				cache.AddAZ(&mysql.AZ{Base: mysql.Base{ID: 2, Lcuuid: "az_lcuuid"}})
				cache.AddVPCs([]*mysql.VPC{{Base: mysql.Base{ID: 3, Lcuuid: "vpc_lcuuid"}}})
				cache.AddHost(&mysql.Host{
					Base:   mysql.Base{ID: 4, Lcuuid: "host_lcuuid"},
					IP:     "10.233.101.79",
					Region: "region_lcuuid",
					AZ:     "az_lcuuid",
				})
				cache.AddVM(&mysql.VM{
					Base: mysql.Base{
						ID:     1,
						Lcuuid: "vm_lcuuid",
					},
					Name:         "vm_name",
					Region:       "region_lcuuid",
					AZ:           "az_lcuuid",
					VPCID:        3,
					LaunchServer: "10.233.101.79",
				})
			},
			assertion: func(t *testing.T, e *eventapi.ResourceEvent) {
				assert.Equal(t, uint32(1), e.InstanceID)
				assert.Equal(t, "vm_name", e.InstanceName)
				assert.Equal(t, fmt.Sprintf("%s,%s", VMStateToString[common.VM_STATE_EXCEPTION],
					VMStateToString[common.VM_STATE_RUNNING]), e.Description)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cache = &cache.Cache{
				DiffBaseDataSet: diffbase.NewDataSet(),
				ToolDataSet:     tool.NewDataSet(),
			}
			tt.prepare(tt.cache)
			tt.v = NewVM(tt.cache.ToolDataSet, NewEventQueue())
			tt.v.ProduceByUpdate(tt.args.cloudItem, tt.args.diffBase)

			e := tt.v.EventManagerBase.Queue.Get().(*eventapi.ResourceEvent)
			tt.assertion(t, e)
		})
	}
}
