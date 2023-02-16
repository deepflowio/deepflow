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

package scheduler

import (
	"context"
	"sync"
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data"
)

var (
	timerOnce sync.Once
	timer     *Timer
)

type Timer struct {
	tCtx             context.Context
	interval         time.Duration
	schedulerManager *SchedulerManager
	redisCfg         redis.RedisConfig
}

func GetTimer(tCtx context.Context, interval int) *Timer {
	timerOnce.Do(func() {
		timer = &Timer{
			tCtx:     tCtx,
			interval: time.Duration(interval) * time.Second,
		}
	})
	return timer
}

func (t *Timer) Start() {
	t.AddTask()

	ticker := time.NewTicker(t.interval)
	go func() {
	LOOP:
		for {
			select {
			case <-ticker.C:
				t.AddTask()
			case <-t.tCtx.Done():
				break LOOP
			}
		}
	}()
}

func (t *Timer) AddTask() {
	schedulerMng := GetSchedulerManager()
	schedulerMng.TryCreateTask(common.RESOURCE_TYPE_VM_EN, data.GetDataProvider(common.RESOURCE_TYPE_VM_EN, t.redisCfg), nil)
	schedulerMng.TryCreateTask(common.RESOURCE_TYPE_POD_EN, data.GetDataProvider(common.RESOURCE_TYPE_POD_EN, t.redisCfg), nil)
}
