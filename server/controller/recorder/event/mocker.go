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

package event

import (
	"math/rand"
	"time"

	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/google/uuid"
)

func RandID() int {
	rand.Seed(time.Now().UnixNano())
	time.Sleep(time.Millisecond)
	return rand.Intn(9999)
}

func RandLcuuid() string {
	return uuid.NewString()
}

func RandName() string {
	return uuid.NewString()[:7]
}

func NewEventQueue() *queue.OverwriteQueue {
	return queue.NewOverwriteQueue(
		"controller-to-ingester-resource_event", 1<<4,
		queue.OptionFlushIndicator(time.Second*3),
		queue.OptionRelease(func(p interface{}) { p.(*eventapi.ResourceEvent).Release() }))
}
