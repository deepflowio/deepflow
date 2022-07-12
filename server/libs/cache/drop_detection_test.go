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

package cache

import (
	"testing"
)

func TestDropdetection(t *testing.T) {
	d := &DropDetection{}
	d.Init("name", 64)

	d.Detect(1, 1, 1)
	d.Detect(1, 3, 3)     // dropped + 1
	d.Detect(1, 5, 5)     // dropped + 1
	d.Detect(1, 100, 100) // dropped + 31
	counter := d.GetCounter().(*DropCounter)
	if counter.Dropped != 33 || counter.Disorder != 0 || counter.DisorderSize != 0 {
		t.Errorf("TestDropdetection dropped error: %v", counter)
	}

	d.Detect(2, 1, 1)
	d.Detect(2, 3, 3) // dropped + 1
	d.Detect(2, 4, 4)
	d.Detect(2, 69, 69) // dropped + 1
	d.Detect(2, 2, 2)   // disorder + 1, disorderSize = 5
	counter = d.GetCounter().(*DropCounter)
	if counter.Dropped != 2 || counter.Disorder != 1 || counter.DisorderSize != 4 {
		t.Errorf("TestDropdetection dropped error: %v", counter)
	}

	d.Detect(2, 1, 0)
	d.Detect(2, 3, 0) // dropped + 1
	d.Detect(2, 4, 0)
	d.Detect(2, 69, 0) // dropped + 1
	d.Detect(2, 2, 0)  // disorder + 1, disorderSize = 5
	counter = d.GetCounter().(*DropCounter)
	if counter.Dropped != 2 || counter.Disorder != 1 || counter.DisorderSize != 4 {
		t.Errorf("TestDropdetection dropped error: %v", counter)
	}

	d.Detect(3, 1, 1)
	d.Detect(3, 3, 3)     // dropped + 1
	d.Detect(3, 5, 5)     // dropped + 1
	d.Detect(3, 100, 100) // dropped + 31
	d.Detect(3, 35, 130)
	if counter.Dropped != 2 || counter.Disorder != 1 || counter.DisorderSize != 4 {
		t.Errorf("TestDropdetection dropped error: %v", counter)
	}
}
