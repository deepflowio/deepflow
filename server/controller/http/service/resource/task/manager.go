/**
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

package task

import (
	"context"
	"sync"

	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/provider"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/filter/generator"
)

var log = logging.MustGetLogger("http.service.resource.task")

var (
	managerOnce sync.Once
	manager     *Manager
)

type Manager struct {
	lock         sync.Mutex
	taskID       int
	schedulerMap map[string]*Scheduler
	configs      *RequiredConfigs
}

func GetManager() *Manager {
	managerOnce.Do(func() {
		manager = &Manager{schedulerMap: make(map[string]*Scheduler)}
	})
	return manager
}

func (m *Manager) Start(ctx context.Context, fCfg config.FPermit, rCfg redis.Config) {
	m.configs = &RequiredConfigs{
		FPermit: fCfg,
		Redis:   rCfg,
	}
	m.schedulerMap = make(map[string]*Scheduler)
	for _, rt := range []string{
		common.RESOURCE_TYPE_VM_EN,
		common.RESOURCE_TYPE_VINTERFACE_EN,
		common.RESOURCE_TYPE_IP_EN, // TODO add all-ips
		common.RESOURCE_TYPE_POD_CLUSTER_EN,
		common.RESOURCE_TYPE_POD_NODE_EN,
		common.RESOURCE_TYPE_POD_NAMESPACE_EN,
		common.RESOURCE_TYPE_POD_INGRESS_EN,
		common.RESOURCE_TYPE_POD_SERVICE_EN,
		common.RESOURCE_TYPE_POD_GROUP_EN,
		common.RESOURCE_TYPE_POD_REPLICA_SET_EN,
		common.RESOURCE_TYPE_POD_EN,
	} {
		s := NewScheduler(ctx, rt)
		go s.Start()
		manager.schedulerMap[rt] = s
	}
}

func (m *Manager) Stop() {
	for _, s := range m.schedulerMap {
		s.Stop()
	}
	log.Info("resource tasks stopped")
}

func (m *Manager) allocateTaskID() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.taskID++
	return m.taskID
}

func (m *Manager) TryCreateTask(resourceType string, urlInfo *model.URLInfo, userInfo *model.UserInfo) (taskID int) {
	if s, ok := m.schedulerMap[resourceType]; ok {
		nextTask := s.setNextIfNil(
			NewTask(
				m.allocateTaskID(),
				resourceType,
				data.GetDataProvider(resourceType, &data.RequiredConfigs{Redis: m.configs.Redis}),
				provider.NewDataContext(urlInfo, userInfo, generator.Get(resourceType, &generator.RequiredConfigs{FPermit: m.configs.FPermit})),
			))
		taskID = nextTask.ID
	}
	return
}

func (m *Manager) CheckTaskDone(id int) int {
	for _, s := range m.schedulerMap {
		in, done := s.isTaskDone(id)
		if !in {
			continue
		}
		if done {
			return 1
		} else {
			return 0
		}
	}
	return 1
}

func (m *Manager) GetTasks() []*Task {
	var tasks []*Task
	for _, s := range m.schedulerMap {
		tasks = append(tasks, s.getTasks()...)
	}
	return tasks
}

type RequiredConfigs struct {
	Redis   redis.Config
	FPermit config.FPermit
}
