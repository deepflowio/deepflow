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

package queue

import (
	"math"
	"testing"
)

func TestManager(t *testing.T) {
	m := NewManager(1)

	unmarshaller := func(_ interface{}) (interface{}, error) {
		return nil, nil
	}

	m.RecvCommand(nil, nil, math.MaxUint16, nil)
	m.NewQueue("1", 1024)
	if _, ok := m.queues["1"]; !ok {
		t.Error("NewQueue error")
	}
	m.NewQueues("2", 1024, 1, 1)
	if _, ok := m.queues["2"]; !ok {
		t.Error("NewQueues error")
	}
	m.NewQueueUnmarshal("3", 1024, unmarshaller)
	if _, ok := m.queues["3"]; !ok {
		t.Error("NewQueueUnmarshal error")
	}
	m.NewQueuesUnmarshal("4", 1024, 1, 1, unmarshaller)
	if _, ok := m.queues["4"]; !ok {
		t.Error("NewQueuesUnmarshal error")
	}
	cmd := RegisterCommand(1, nil)
	if cmd == nil {
		t.Error("RegisterCommand error")
	}
}
