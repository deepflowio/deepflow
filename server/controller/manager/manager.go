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

package manager

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set"
	logging "github.com/op/go-logging"

	cloudcfg "github.com/deepflowio/deepflow/server/controller/cloud/config"
	kubernetes_gather_model "github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/model"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/manager/config"
	"github.com/deepflowio/deepflow/server/controller/recorder"
	recordercfg "github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

var log = logging.MustGetLogger("manager")

type Manager struct {
	cfg                config.ManagerConfig
	taskMap            map[string]*Task
	mutex              sync.RWMutex
	resourceEventQueue *queue.OverwriteQueue
}

func NewManager(cfg config.ManagerConfig, resourceEventQueue *queue.OverwriteQueue) *Manager {
	return &Manager{
		cfg:                cfg,
		taskMap:            make(map[string]*Task),
		resourceEventQueue: resourceEventQueue,
	}
}

func (m *Manager) GetCloudInfo(lcuuid string) (model.BasicInfo, error) {
	var cloudInfo model.BasicInfo

	m.mutex.RLock()
	defer m.mutex.RUnlock()
	task, ok := m.taskMap[lcuuid]
	if !ok {
		return model.BasicInfo{}, errors.New(fmt.Sprintf("domain (%s) not found", lcuuid))
	}
	cloudInfo = task.Cloud.GetBasicInfo()
	return cloudInfo, nil
}

func (m *Manager) GetCloudInfos() []model.BasicInfo {
	var cloudInfos []model.BasicInfo

	m.mutex.RLock()
	defer m.mutex.RUnlock()
	for _, task := range m.taskMap {
		cloudInfos = append(cloudInfos, task.Cloud.GetBasicInfo())
	}
	return cloudInfos
}

func (m *Manager) GetCloudResource(lcuuid string) (model.Resource, error) {
	var cloudResource model.Resource

	m.mutex.RLock()
	defer m.mutex.RUnlock()
	task, ok := m.taskMap[lcuuid]
	if !ok {
		return model.Resource{}, errors.New(fmt.Sprintf("domain (%s) not found", lcuuid))
	}
	cloudResource = task.Cloud.GetResource()
	return cloudResource, nil
}

func (m *Manager) GetKubernetesGatherBasicInfos(lcuuid string) ([]kubernetes_gather_model.KubernetesGatherBasicInfo, error) {
	var k8sGatherBasicInfos []kubernetes_gather_model.KubernetesGatherBasicInfo

	m.mutex.RLock()
	defer m.mutex.RUnlock()
	cloudTask, ok := m.taskMap[lcuuid]
	if !ok {
		return nil, errors.New(fmt.Sprintf("domain (%s) not found", lcuuid))
	}
	k8sGatherTaskMap := cloudTask.Cloud.GetKubernetesGatherTaskMap()
	for _, k8sGatherTask := range k8sGatherTaskMap {
		k8sGatherBasicInfos = append(k8sGatherBasicInfos, k8sGatherTask.GetBasicInfo())
	}
	return k8sGatherBasicInfos, nil
}

func (m *Manager) GetKubernetesGatherResources(lcuuid string) ([]kubernetes_gather_model.KubernetesGatherResource, error) {
	var k8sGatherResources []kubernetes_gather_model.KubernetesGatherResource

	m.mutex.RLock()
	defer m.mutex.RUnlock()
	cloudTask, ok := m.taskMap[lcuuid]
	if !ok {
		return nil, errors.New(fmt.Sprintf("domain (%s) not found", lcuuid))
	}
	k8sGatherTaskMap := cloudTask.Cloud.GetKubernetesGatherTaskMap()
	for _, k8sGatherTask := range k8sGatherTaskMap {
		k8sGatherResources = append(k8sGatherResources, k8sGatherTask.GetResource())
	}
	return k8sGatherResources, nil
}

func (m *Manager) TriggerKubernetesRefresh(domainLcuuid, subDomainLcuuid string, version int) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	cloudTask, ok := m.taskMap[domainLcuuid]
	if !ok {
		return errors.New(fmt.Sprintf("domain (%s) not found", domainLcuuid))
	}
	k8sGatherTaskMap := cloudTask.Cloud.GetKubernetesGatherTaskMap()
	gather, ok := k8sGatherTaskMap[subDomainLcuuid]
	if !ok {
		return errors.New(fmt.Sprintf("domain (%s) not found gather (%s)", domainLcuuid, subDomainLcuuid))
	}
	return gather.PutRefreshSignal(version)
}

func (m *Manager) GetRecorder(domainLcuuid string) (recorder.Recorder, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	task, ok := m.taskMap[domainLcuuid]
	if !ok {
		return recorder.Recorder{}, errors.New(fmt.Sprintf("task of domain (lcuuid: %s) not found", domainLcuuid))
	}
	return *task.Recorder, nil
}

func (m *Manager) run(ctx context.Context) {
	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		log.Error("get org ids failed")
		return
	}

	for _, orgID := range orgIDs {
		db, err := mysql.GetDB(orgID)
		if err != nil {
			log.Errorf("get org id (%d) mysql session failed", orgID)
			continue
		}
		// 获取所在控制器的IP
		var controller mysql.Controller
		hostName := common.GetNodeName()
		if len(hostName) == 0 {
			log.Error("hostname is null")
			return
		}
		if ret := db.Where("name = ?", hostName).First(&controller); ret.Error != nil {
			log.Errorf("controller (%s) not in db", hostName)
			return
		}

		var domains []mysql.Domain
		var oldDomains = mapset.NewSet()
		var newDomains = mapset.NewSet()
		var delDomains = mapset.NewSet()
		var addDomains = mapset.NewSet()
		var intersectDomains = mapset.NewSet()

		for lcuuid, task := range m.taskMap {
			if task == nil {
				continue
			}
			if task.Cloud == nil {
				continue
			}
			if task.Cloud.GetOrgID() != orgID {
				continue
			}
			oldDomains.Add(lcuuid)
		}
		db.Where(
			"enabled = ? AND controller_ip = ?", common.DOMAIN_ENABLED_TRUE, controller.IP,
		).Find(&domains)
		lcuuidToDomain := make(map[string]mysql.Domain)
		for _, domain := range domains {
			lcuuidToDomain[domain.Lcuuid] = domain
			newDomains.Add(domain.Lcuuid)
		}

		// 对于删除的domain，停止Task，并移除管理
		delDomains = oldDomains.Difference(newDomains)
		for _, domain := range delDomains.ToSlice() {
			lcuuid := domain.(string)
			m.taskMap[lcuuid].Stop()
			m.mutex.Lock()
			delete(m.taskMap, lcuuid)
			m.mutex.Unlock()
		}

		// 对于新增的domain，启动Task，并纳入Manager管理
		addDomains = newDomains.Difference(oldDomains)
		for _, domain := range addDomains.ToSlice() {
			lcuuid := domain.(string)
			task := NewTask(orgID, lcuuidToDomain[lcuuid], m.cfg.TaskCfg, ctx, m.resourceEventQueue)
			if task == nil || task.Cloud == nil {
				log.Errorf("domain (%s) init failed", lcuuidToDomain[lcuuid].Name)
				continue
			}
			m.mutex.Lock()
			m.taskMap[lcuuid] = task
			m.taskMap[lcuuid].Start()
			m.mutex.Unlock()
		}

		// 检查已有domain是否存在配置/名称修改
		// 如果存在配置修改，则停止已有Task，并移除管理；同时启动新的Task，并纳入Manager管理
		// 如果没有配置修改，判断是否存在名称修改更新Task信息
		intersectDomains = newDomains.Intersect(oldDomains)
		for _, domain := range intersectDomains.ToSlice() {
			lcuuid := domain.(string)
			oldDomainConfig := m.taskMap[lcuuid].DomainConfig
			newDomainConfig := lcuuidToDomain[lcuuid].Config
			if oldDomainConfig != newDomainConfig {
				log.Infof("oldDomainConfig: %s", oldDomainConfig)
				log.Infof("newDomainConfig: %s", newDomainConfig)
				m.taskMap[lcuuid].Stop()
				task := NewTask(orgID, lcuuidToDomain[lcuuid], m.cfg.TaskCfg, ctx, m.resourceEventQueue)
				if task == nil || task.Cloud == nil {
					log.Errorf("domain (%s) init failed", lcuuidToDomain[lcuuid].Name)
					continue
				}

				m.mutex.Lock()
				delete(m.taskMap, lcuuid)
				m.taskMap[lcuuid] = task
				m.taskMap[lcuuid].Start()
				m.mutex.Unlock()
			} else {
				oldDomainName := m.taskMap[lcuuid].DomainName
				newDomainName := lcuuidToDomain[lcuuid].Name
				if oldDomainName != newDomainName {
					if m.taskMap[lcuuid].Cloud.GetBasicInfo().Type == common.KUBERNETES {
						m.taskMap[lcuuid].Stop()
						task := NewTask(orgID, lcuuidToDomain[lcuuid], m.cfg.TaskCfg, ctx, m.resourceEventQueue)
						if task == nil || task.Cloud == nil {
							log.Errorf("domain (%s) init failed", lcuuidToDomain[lcuuid].Name)
							continue
						}

						m.mutex.Lock()
						delete(m.taskMap, lcuuid)
						m.taskMap[lcuuid] = task
						m.taskMap[lcuuid].Start()
						m.mutex.Unlock()
					} else {
						m.taskMap[lcuuid].UpdateDomainName(newDomainName)
					}
				}
			}
		}
	}
}

func (m *Manager) Start() {
	cloudcfg.SetCloudGlobalConfig(m.cfg.TaskCfg.CloudCfg)
	recordercfg.Set(&m.cfg.TaskCfg.RecorderCfg)

	log.Info("manager started")
	ctx := context.Context(context.Background())
	go func() {
		m.run(ctx)
		for range time.Tick(time.Duration(m.cfg.CloudConfigCheckInterval) * time.Second) {
			m.run(ctx)
		}
	}()
}
