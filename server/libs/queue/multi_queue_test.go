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
	"sync"
	"testing"
)

func TestMultiQueue(t *testing.T) {
	queue := NewOverwriteQueues("whatever", 15, 1)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if item := queue.Get(7); item != 10086 {
			t.Errorf("Expected 10086, actually %d", item)
		}
		wg.Done()
	}()
	queue.Put(7, 10086)
	wg.Wait()
	if len(queue) != 16 {
		t.Errorf("Expected 16, actually %d", len(queue))
	}
}
