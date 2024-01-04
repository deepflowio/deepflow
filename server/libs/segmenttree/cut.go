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

package segmenttree

const (
	POSITIVE_INFINITY = int64(^uint64(0) >> 1)
	NEGATIVE_INFINITY = -POSITIVE_INFINITY - 1
)

type Cut struct {
	endpoint int64
	closed   bool // bound等于正无穷或负无穷时，closed无效
}

func (c *Cut) compareTo(o Cut) int {
	if c.endpoint > o.endpoint {
		return 1
	} else if c.endpoint < o.endpoint {
		return -1
	} else if c.closed != o.closed {
		if c.closed {
			return 1
		} else {
			return -1
		}
	} else {
		return 0
	}
}

func (c *Cut) hasBound() bool {
	return c.endpoint != POSITIVE_INFINITY && c.endpoint != NEGATIVE_INFINITY
}
