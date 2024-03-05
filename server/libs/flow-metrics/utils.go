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

package flow_metrics

import "time"

func maxU64(vs ...uint64) uint64 {
	if len(vs) == 0 {
		panic("no number provided")
	}
	max := vs[0]
	for _, v := range vs {
		if v > max {
			max = v
		}
	}
	return max
}

func minU64(vs ...uint64) uint64 {
	if len(vs) == 0 {
		panic("no number provided")
	}
	min := vs[0]
	for _, v := range vs {
		if v < min {
			min = v
		}
	}
	return min
}

func maxDuration(x, y time.Duration) time.Duration {
	if x > y {
		return x
	}
	return y
}

func minDuration(x, y time.Duration) time.Duration {
	if x == 0 || y == 0 {
		return x + y
	}
	if x < y {
		return x
	}
	return y
}
