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

package timedtagmap

import (
	"strconv"
	"testing"
)

func TestTimedTagMapGetID(t *testing.T) {
	ttm := NewTimedTagMap("t", 1, 4)

	id := ttm.GetID("a", 10)
	exp := 0
	if id != exp {
		t.Errorf("1. 第一次查询，Expected %v found %v", exp, id)
	}

	id = ttm.GetID("a", 10)
	exp = 0
	if id != exp {
		t.Errorf("2. 查询已有的时间、已有的Tag，Expected %v found %v", exp, id)
	}

	id = ttm.GetID("b", 10)
	exp = 1
	if id != exp {
		t.Errorf("3. 查询已有的时间、新Tag，Expected %v found %v", exp, id)
	}

	id = ttm.GetID("b", 11)
	exp = 0
	if id != exp {
		t.Errorf("4. 查询新的时间、已有的Tag，Expected %v found %v", exp, id)
	}

	id = ttm.GetID("c", 13)
	exp = 0
	if id != exp {
		t.Errorf("5. 查询新的时间、新的Tag，Expected %v found %v", exp, id)
	}

	id = ttm.GetID("a", 13)
	exp = 1
	if id != exp {
		t.Errorf("6. 查询已有的时间、已有的Tag，恰未过期，Expected %v found %v", exp, id)
	}

	id = ttm.GetID("c", 17)
	exp = 0
	if id != exp {
		t.Errorf("7. 查询新的时间、已有的Tag，恰过期，Expected %v found %v", exp, id)
	}
}

func BenchmarkTimedTagMapGetID(b *testing.B) {
	tags := make([]string, 300000)
	for i := range tags {
		tags[i] = strconv.Itoa(i + 1000000000)
	}

	b.ResetTimer()
	ttm := NewTimedTagMap("t", 1, 30)
	for i := 0; i < b.N; {
		for j := 0; j < 20; j++ {
			for _, tag := range tags {
				ttm.GetID(tag, i)
				i++
			}
		}
	}
}

func BenchmarkMapGetID(b *testing.B) {
	tags := make([]string, 300000)
	for i := range tags {
		tags[i] = strconv.Itoa(i + 1000000000)
	}

	b.ResetTimer()
	for i := 0; i < b.N; {
		tagMap := make(map[string]int)
		for j := 0; j < 20; j++ {
			for _, tag := range tags {
				if _, ok := tagMap[tag]; !ok {
					tagMap[tag] = len(tagMap)
				}
				i++
			}
		}
	}
}
