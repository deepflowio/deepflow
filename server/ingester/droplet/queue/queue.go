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
	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type Queue struct {
	*queue.OverwriteQueue
	*Monitor
}

func (q *Queue) Init(name string, size int, unmarshaller Unmarshaller, options ...queue.Option) {
	q.Monitor = &Monitor{}
	q.Monitor.init(name, unmarshaller)
	q.OverwriteQueue = &queue.OverwriteQueue{}
	options = append(options, common.QUEUE_STATS_MODULE_INGESTER)
	q.OverwriteQueue.Init(name, size, options...)
}

func (q *Queue) Get() interface{} {
	return q.OverwriteQueue.Get()
}

func (q *Queue) Gets(output []interface{}) int {
	return q.OverwriteQueue.Gets(output)
}

func (q *Queue) Put(items ...interface{}) error {
	q.Monitor.send(items)
	return q.OverwriteQueue.Put(items...)
}

func (q *Queue) Len() int {
	return q.OverwriteQueue.Len()
}
