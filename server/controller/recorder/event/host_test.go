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
	"testing"

	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	"github.com/deepflowys/deepflow/server/libs/eventapi"
	"github.com/stretchr/testify/assert"
)

func TestHost_ProduceByAdd(t *testing.T) {
	dataSet := cache.NewToolDataSet()
	type args struct {
		items []*mysql.Host
	}
	tests := []struct {
		name     string
		h        *Host
		args     args
		wantID   uint32
		wantName string
	}{
		{
			name: "add success",
			h:    NewHost(&dataSet, NewEventQueue()),
			args: args{
				items: []*mysql.Host{
					{
						Base: mysql.Base{ID: 1},
						Name: "host",
					},
				},
			},
			wantID:   1,
			wantName: "host",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.h.ProduceByAdd(tt.args.items)

			e := tt.h.EventManager.Queue.Get().(*eventapi.ResourceEvent)
			assert.Equal(t, tt.wantID, e.ResourceID)
			assert.Equal(t, tt.wantName, e.ResourceName)
		})
	}
}

func TestHost_ProduceByDelete(t *testing.T) {
	type args struct {
		lcuuids []string
	}
	tests := []struct {
		name     string
		dataSet  cache.ToolDataSet
		h        *Host
		args     args
		wantID   uint32
		wantName string
	}{
		{
			name: "delete success",
			dataSet: cache.ToolDataSet{
				HostLcuuidToID: map[string]int{
					"ff6f9b99-82ef-5507-b6b6-cbab28bda9cb": 1,
				},
				EventToolDataSet: cache.EventToolDataSet{
					HostIDToName: map[int]string{
						1: "host",
					},
				},
			},
			args: args{
				lcuuids: []string{"ff6f9b99-82ef-5507-b6b6-cbab28bda9cb"},
			},
			wantID:   1,
			wantName: "host",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.h = NewHost(&tt.dataSet, NewEventQueue())
			tt.h.ProduceByDelete(tt.args.lcuuids)

			e := tt.h.EventManager.Queue.Get().(*eventapi.ResourceEvent)
			assert.Equal(t, tt.wantID, e.ResourceID)
			assert.Equal(t, tt.wantName, e.ResourceName)
		})
	}
}
