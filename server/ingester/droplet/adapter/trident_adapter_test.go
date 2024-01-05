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

package adapter

import (
	"math"
	"reflect"
	"testing"

	"github.com/deepflowio/deepflow/server/ingester/droplet/queue"
)

func TestTridentAdapter(t *testing.T) {
	manager := queue.NewManager(1)
	queues := manager.NewQueues("1-meta-packet-block-to-labeler", 1<<10, 1, 1)
	adapter := NewTridentAdapter(nil, queues.Writers(), 1<<20)

	count := adapter.GetStatsCounter()
	if !reflect.DeepEqual(count, &PacketCounter{}) {
		t.Errorf("GetStatsCounter expect %v actual: %v", &PacketCounter{}, count)
	}
	count = adapter.GetCounter()
	if !reflect.DeepEqual(count, &PacketCounter{}) {
		t.Errorf("GetCounter expect %v actual: %v", &PacketCounter{}, count)
	}
	instances := adapter.GetInstances()
	if len(instances) > 0 {
		t.Errorf("GetInstances expect %v actual: %v", 0, len(instances))
	}
	// command test
	adapter.RecvCommand(nil, nil, math.MaxUint16, nil)
	cobra := RegisterCommand(1)
	if cobra == nil {
		t.Error("RegisterCommand return nil")
	}
}
