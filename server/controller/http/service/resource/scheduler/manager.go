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

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/provider"
)

// TODO only for master controller
var (
	managerOnce sync.Once
	manager     *SchedulerManager
)

type SchedulerManager struct {
	lock         sync.Mutex
	taskID       int
	schedulerMap map[string]*Scheduler
}

func GetSchedulerManager() *SchedulerManager {
	managerOnce.Do(func() {
		manager = &SchedulerManager{}
	})
	return manager
}

func (m *SchedulerManager) Start(ctx context.Context) {
	m.schedulerMap = make(map[string]*Scheduler)
	m.schedulerMap[common.RESOURCE_TYPE_POD_EN] = NewScheduler(ctx)
	for _, s := range m.schedulerMap {
		go s.Run()
	}
}

func (m *SchedulerManager) allocateTaskID() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.taskID++
	return m.taskID
}

func (m *SchedulerManager) TryCreateTask(rt string, dp provider.DataRefresher, dc *provider.DataContext) (taskID int) {
	if s, ok := m.schedulerMap[rt]; ok {
		nextTask := s.SetNextIfNil(NewTask(m.allocateTaskID(), rt, dp, dc))
		taskID = nextTask.ID
	}
	return
}

func (m *SchedulerManager) CheckTaskDone(rt string, id int) bool {
	if s, ok := m.schedulerMap[rt]; ok {
		return s.IsTaskDone(id)
	}
	return true
}
