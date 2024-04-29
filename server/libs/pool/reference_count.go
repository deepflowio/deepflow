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

package pool

import (
	"runtime/debug"
	"sync/atomic"
	"time"
)

type ReferenceCount int32

var lastStackDump int64

func (r *ReferenceCount) Reset() {
	*r = 1
}

func (r *ReferenceCount) AddReferenceCount() {
	atomic.AddInt32((*int32)(r), 1)
}

func (r *ReferenceCount) AddReferenceCountN(n int32) {
	atomic.AddInt32((*int32)(r), n)
}

func (r *ReferenceCount) SubReferenceCount() bool {
	if atomic.AddInt32((*int32)(r), -1) > 0 {
		return true
	}
	if *r != 0 {
		now := time.Now().Unix()
		last := atomic.LoadInt64(&lastStackDump)
		if now-last > int64(time.Hour/time.Second) {
			log.Errorf("reference (%d) maybe double released\n%s", *r, string(debug.Stack()))
			atomic.StoreInt64(&lastStackDump, now)
		}
	}
	return false
}

func (r *ReferenceCount) GetReferenceCount() int32 {
	return atomic.LoadInt32((*int32)(r))
}
