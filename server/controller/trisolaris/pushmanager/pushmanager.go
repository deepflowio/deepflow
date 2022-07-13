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

package pushmanager

import (
	"sync"
)

type PushManager struct {
	c *sync.Cond
}

var pushManager *PushManager = NewPushManager()

func NewPushManager() *PushManager {
	return &PushManager{
		c: sync.NewCond(&sync.Mutex{}),
	}
}

func Broadcast() {
	pushManager.c.Broadcast()
}

func Wait() {
	pushManager.c.L.Lock()
	pushManager.c.Wait()
	pushManager.c.L.Unlock()
}
