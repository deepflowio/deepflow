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
	"time"

	"github.com/deepflowio/deepflow/server/libs/stats"
)

const MAX_QUEUE_COUNT = 16

type HashKey = uint8

type Option = interface{}

type OptionRelease = func(x interface{})
type OptionStatsOption = stats.Option
type OptionFlushIndicator = time.Duration // scheduled put nil into queue
type OptionModule = string

type QueueReader interface {
	Get() interface{}
	Gets([]interface{}) int
	Len() int
	Close() error
}

type QueueWriter interface {
	Put(...interface{}) error
	Len() int
	Close() error
}

type MultiQueueReader interface {
	Get(HashKey) interface{}
	Gets(HashKey, []interface{}) int
	Len(HashKey) int
	Close() error
}

type MultiQueueWriter interface {
	Put(HashKey, ...interface{}) error
	Puts([]HashKey, []interface{}) error
	Len(HashKey) int
	Close() error
}
