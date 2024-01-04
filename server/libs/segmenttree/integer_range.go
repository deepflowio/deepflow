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

/**
 * 仅在包内使用，因此对于负无穷和正无穷的判断会省略掉
 */
package segmenttree

type IntegerRange struct {
	lower, upper Cut
}

func (r *IntegerRange) lowerEndpoint() Endpoint {
	return r.lower.endpoint
}

func (r *IntegerRange) upperEndpoint() Endpoint {
	return r.upper.endpoint
}

func (r *IntegerRange) lowerClosed() bool {
	return r.lower.closed
}

func (r *IntegerRange) upperClosed() bool {
	return r.upper.closed
}

func (r *IntegerRange) hasLowerBound() bool {
	return r.lower.hasBound()
}

func (r *IntegerRange) hasUpperBound() bool {
	return r.upper.hasBound()
}

func (r *IntegerRange) encloses(other *IntegerRange) bool {
	return r.lower.compareTo(other.lower) <= 0 && r.upper.compareTo(other.upper) >= 0
}

func (r *IntegerRange) isEmpty() bool {
	return r.lower.endpoint == r.upper.endpoint && (!r.lowerClosed() || !r.upperClosed())
}

// [1, 3) and [3, 4) is connected, [1, 3) and [2, 4] is connected, [1, 3) and (3, 4) is not connected
// FIXME: 对于[1, 3) [3, 4]的情形，isConnected判断有误，不过好在对于线段树的使用并不影响
func (r *IntegerRange) isConnected(other *IntegerRange) bool {
	return r.lower.compareTo(other.upper) <= 0 && other.lower.compareTo(r.upper) <= 0
}

func (r *IntegerRange) intersection(other *IntegerRange) IntegerRange {
	lowerCmp := r.lower.compareTo(other.lower)
	upperCmp := r.upper.compareTo(other.upper)
	if lowerCmp >= 0 && upperCmp <= 0 {
		return *r
	} else if lowerCmp <= 0 && upperCmp >= 0 {
		return *other
	} else {
		var lower, upper Cut
		if lowerCmp >= 0 {
			lower = r.lower
		} else {
			lower = other.lower
		}
		if upperCmp <= 0 {
			upper = r.upper
		} else {
			upper = other.upper
		}
		return IntegerRange{lower, upper}
	}
}

var (
	RANGE_ALL   = IntegerRange{Cut{NEGATIVE_INFINITY, false}, Cut{POSITIVE_INFINITY, false}}
	RANGE_EMPTY = IntegerRange{Cut{0, false}, Cut{0, false}}
)

func upToRange(upper Endpoint, upperClosed bool) IntegerRange {
	return IntegerRange{Cut{NEGATIVE_INFINITY, false}, Cut{upper, upperClosed}}
}

func downToRange(lower Endpoint, lowerClosed bool) IntegerRange {
	return IntegerRange{Cut{lower, lowerClosed}, Cut{POSITIVE_INFINITY, false}}
}

func ranged(lower Endpoint, lowerClosed bool, upper Endpoint, upperClosed bool) IntegerRange {
	return IntegerRange{Cut{lower, lowerClosed}, Cut{upper, upperClosed}}
}
