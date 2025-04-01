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

	cloudcfg "github.com/deepflowio/deepflow/server/controller/cloud/config"
	gathermodel "github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/model"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/manager/config"
	"github.com/deepflowio/deepflow/server/controller/recorder"
	recordercfg "github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("manager")

type Manager struct {
	cfg     config.ManagerConfig
	taskMap map[string]*Task
	mutex   sync.RWMutex
}

func NewManager(cfg config.ManagerConfig) *Manager {
	return &Manager{
		cfg:     cfg,
		taskMap: make(map[string]*Task),
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

func (m *Manager) TriggerDomain(lcuuid string) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	task, ok := m.taskMap[lcuuid]
	if !ok {
		return fmt.Errorf("domain (%s) not found", lcuuid)
	}
	return task.Cloud.ClientTrigger()
}

func (m *Manager) GetKubernetesGatherBasicInfos(lcuuid string) ([]gathermodel.KubernetesGatherBasicInfo, error) {
	var k8sGatherBasicInfos []gathermodel.KubernetesGatherBasicInfo

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

func (m *Manager) GetSubDomainResource(lcuuid, subDomainLcuuid string) (model.SubDomainResource, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	cloudTask, ok := m.taskMap[lcuuid]
	if !ok {
		return model.SubDomainResource{}, fmt.Errorf("domain (%s) not found", lcuuid)
	}
	cResource := cloudTask.Cloud.GetSubDomainResource(subDomainLcuuid)

	return cResource.SubDomainResources[subDomainLcuuid], nil
}

func (m *Manager) GetKubernetesGatherResource(lcuuid, subDomainLcuuid string) (gathermodel.KubernetesGatherResource, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	cloudTask, ok := m.taskMap[lcuuid]
	if !ok {
		return gathermodel.KubernetesGatherResource{}, fmt.Errorf("domain (%s) not found", lcuuid)
	}

	k8sGatherTaskMap := cloudTask.Cloud.GetKubernetesGatherTaskMap()
	k8sGather, ok := k8sGatherTaskMap[subDomainLcuuid]
	if !ok {
		return gathermodel.KubernetesGatherResource{}, fmt.Errorf("sub domain (%s) not found", subDomainLcuuid)
	}

	return k8sGather.GetResource(), nil
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
	orgIDs, err := metadb.GetORGIDs()
	if err != nil {
		log.Error("get org ids failed")
		return
	}

	for _, orgID := range orgIDs {
		db, err := metadb.GetDB(orgID)
		if err != nil {
			log.Error("get metadb session failed", logger.NewORGPrefix(orgID))
			continue
		}
		// 获取所在控制器的IP
		var controller metadbmodel.Controller
		hostName := common.GetNodeName()
		if len(hostName) == 0 {
			log.Error("hostname is null")
			return
		}
		if ret := db.Where("name = ?", hostName).First(&controller); ret.Error != nil {
			log.Errorf("controller (%s) not in db", hostName)
			return
		}

		var domains []metadbmodel.Domain
		var oldDomainLcuuids = mapset.NewSet()
		var newDomainLcuuids = mapset.NewSet()
		var delDomainLcuuids = mapset.NewSet()
		var addDomainLcuuids = mapset.NewSet()
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
			oldDomainLcuuids.Add(lcuuid)
		}
		db.Where(
			"enabled = ? AND controller_ip = ? AND state != ?",
			common.DOMAIN_ENABLED_TRUE, controller.IP, common.RESOURCE_STATE_CODE_NO_LICENSE,
		).Find(&domains)
		lcuuidToDomain := make(map[string]metadbmodel.Domain)
		for _, domain := range domains {
			lcuuidToDomain[domain.Lcuuid] = domain
			newDomainLcuuids.Add(domain.Lcuuid)
		}

		// 对于删除的domain，停止Task，并移除管理
		delDomainLcuuids = oldDomainLcuuids.Difference(newDomainLcuuids)
		for _, lcuuid := range delDomainLcuuids.ToSlice() {
			deletedLcuuid := lcuuid.(string)
			m.taskMap[deletedLcuuid].Stop()
			m.mutex.Lock()
			delete(m.taskMap, deletedLcuuid)
			m.mutex.Unlock()
		}

		// 对于新增的domain，启动Task，并纳入Manager管理
		addDomainLcuuids = newDomainLcuuids.Difference(oldDomainLcuuids)
		for _, lcuuid := range addDomainLcuuids.ToSlice() {
			addedLcuuid := lcuuid.(string)
			domain := lcuuidToDomain[addedLcuuid]
			task := NewTask(orgID, domain, m.cfg.TaskCfg, ctx)
			if task == nil || task.Cloud == nil {
				log.Errorf("domain (%s) init failed", domain.Name, logger.NewORGPrefix(orgID))
				continue
			}
			m.mutex.Lock()
			m.taskMap[addedLcuuid] = task
			m.taskMap[addedLcuuid].Start()
			m.mutex.Unlock()
		}

		// 检查已有domain是否存在配置/名称修改
		// 如果存在配置修改，则停止已有Task，并移除管理；同时启动新的Task，并纳入Manager管理
		// 如果没有配置修改，判断是否存在名称修改更新Task信息
		intersectDomains = newDomainLcuuids.Intersect(oldDomainLcuuids)
		for _, lcuuid := range intersectDomains.ToSlice() {
			domainLcuuid := lcuuid.(string)
			newDomain := lcuuidToDomain[domainLcuuid]
			oldDomainConfig := m.taskMap[domainLcuuid].DomainConfig
			if oldDomainConfig != newDomain.Config {
				log.Infof("domain (%s) oldDomainConfig: %s", newDomain.Name, oldDomainConfig, logger.NewORGPrefix(orgID))
				log.Infof("domain (%s) newDomainConfig: %s", newDomain.Name, newDomain.Config, logger.NewORGPrefix(orgID))
				m.taskMap[domainLcuuid].Stop()
				task := NewTask(orgID, newDomain, m.cfg.TaskCfg, ctx)
				if task == nil || task.Cloud == nil {
					log.Errorf("domain (%s) init failed", newDomain.Name, logger.NewORGPrefix(orgID))
					continue
				}

				m.mutex.Lock()
				delete(m.taskMap, domainLcuuid)
				m.taskMap[domainLcuuid] = task
				m.taskMap[domainLcuuid].Start()
				m.mutex.Unlock()
			} else {
				oldDomainName := m.taskMap[domainLcuuid].DomainName
				if oldDomainName != newDomain.Name {
					if m.taskMap[domainLcuuid].Cloud.GetBasicInfo().Type == common.KUBERNETES {
						m.taskMap[domainLcuuid].Stop()
						task := NewTask(orgID, newDomain, m.cfg.TaskCfg, ctx)
						if task == nil || task.Cloud == nil {
							log.Errorf("domain (%s) init failed", newDomain.Name, logger.NewORGPrefix(orgID))
							continue
						}

						m.mutex.Lock()
						delete(m.taskMap, domainLcuuid)
						m.taskMap[domainLcuuid] = task
						m.taskMap[domainLcuuid].Start()
						m.mutex.Unlock()
					} else {
						m.taskMap[domainLcuuid].UpdateDomainName(newDomain.Name)
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
