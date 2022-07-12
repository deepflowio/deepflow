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

package queue

import (
	"testing"
)

func TestQueue(t *testing.T) {
	buffer := make([]interface{}, 10)
	m := NewManager(1)

	q := m.NewQueue("1", 1024)
	q.Put(1)
	q.Put(2)
	q.Put(3)
	if q.Len() != 3 {
		t.Errorf("Len expect 3 actual %v", q.Len())
	}
	q.Get()
	n := q.Gets(buffer)
	if n != 2 {
		t.Errorf("Gets expect 2 actual %v", n)
	}
}
