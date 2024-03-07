/*
 * Copyright (c) 2023 Yunshan Networks
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

package stats

import (
	"time"
)

var (
	MinInterval = TICK_CYCLE
)

type RemoteType = uint8

const (
	REMOTE_TYPE_INFLUXDB RemoteType = 1 << iota
	REMOTE_TYPE_STATSD
	REMOTE_TYPE_DFSTATSD
)

const (
	TICK_COUNT = 10
	TICK_CYCLE = TICK_COUNT * time.Second
)

type Option = interface{}
type OptionStatTags = map[string]string
type OptionInterval time.Duration // must be time.Second, time.Minute or time.Hour

type Countable interface {
	// needs to be thread-safe, clear is required after read
	// accept struct or []StatItem
	GetCounter() interface{}

	// once closed, countable will be removed from stats
	Closed() bool
}

// 限定stats的最少interval，也就是不论注册Countable时
// 指定的Interval是多少，只要比此值低就优先使用此值
func SetMinInterval(interval time.Duration) {
	MinInterval = (interval + TICK_CYCLE - 1) / TICK_CYCLE * TICK_CYCLE
	if MinInterval != interval {
		log.Warning("Bad stats-interval:", interval, ", should be integral multiple of", TICK_CYCLE, ",change to", MinInterval)
	}
}

// 指定influxdb远程服务器
// 只会有其中一个远程服务器会收到统计数据
// addr格式: "192.168.1.1:20033"
func SetRemotes(addrs ...string) {
	setRemotes(addrs...)
}

// addr格式: "192.168.1.1:20033"
func SetDFRemote(addr string) {
	setDFRemote(addr)
}

// 指定远程服务器类型，默认influxdb
func SetRemoteType(t RemoteType) {
	remoteType = t
}

func SetHostname(name string) {
	setHostname(name)
}

func SetProcessName(name string) {
	setProcessName(name)
}

func SetProcessNameJoiner(joiner string) {
	setProcessNameJoiner(joiner)
}

func RegisterPreHook(hook func()) {
	lock.Lock()
	preHooks = append(preHooks, hook)
	lock.Unlock()
}

func RegisterCountable(module string, countable Countable, opts ...Option) error {
	return registerCountable("", module, countable, opts...)
}

func RegisterCountableWithModulePrefix(modulePrefix, module string, countable Countable, opts ...Option) error {
	return registerCountable(modulePrefix, module, countable, opts...)
}
