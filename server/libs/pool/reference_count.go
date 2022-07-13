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

package pool

import (
	"sync/atomic"
)

type ReferenceCount int32

func (r *ReferenceCount) Reset() {
	*r = 1
}

func (r *ReferenceCount) AddReferenceCount() {
	atomic.AddInt32((*int32)(r), 1)
}

func (r *ReferenceCount) SubReferenceCount() bool {
	if atomic.AddInt32((*int32)(r), -1) > 0 {
		return true
	}
	if *r != 0 {
		log.Errorf("reference(%d) maybe double released", *r)
	}
	return false
}

func (r *ReferenceCount) GetReferenceCount() int32 {
	return atomic.LoadInt32((*int32)(r))
}
