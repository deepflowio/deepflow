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

package adapter

import (
	"reflect"
	"testing"
)

func TestCounter(t *testing.T) {
	base := &PacketCounter{10, 10, 10, 10, 10}

	statsCounter := &statsCounter{}
	statsCounter.init()

	statsCounter.counter.add(base)
	statsCounter.stats.add(base)

	count := statsCounter.GetStatsCounter()
	if !reflect.DeepEqual(count, base) {
		t.Errorf("GetStatsCounter expect %v actual: %v", base, count)
	}

	count = statsCounter.GetCounter()
	if !reflect.DeepEqual(count, base) {
		t.Errorf("GetCounter expect %v actual: %v", base, count)
	}

	count = statsCounter.GetStatsCounter()
	if !reflect.DeepEqual(count, base) {
		t.Errorf("GetStatsCounter expect %v actual: %v", base, count)
	}

	count = statsCounter.GetCounter()
	if !reflect.DeepEqual(count, &PacketCounter{}) {
		t.Errorf("GetCounter expect %v actual: %v", &PacketCounter{}, count)
	}
}
