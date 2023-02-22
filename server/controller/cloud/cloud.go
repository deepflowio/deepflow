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

package cloud

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set"
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/cloud/platform"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/genesis"
	"github.com/deepflowio/deepflow/server/controller/statsd"
)

var log = logging.MustGetLogger("cloud")

type Cloud struct {
	cfg                     config.CloudConfig
	cCtx                    context.Context
	cCancel                 context.CancelFunc
	mutex                   sync.RWMutex
	basicInfo               model.BasicInfo
	resource                model.Resource
	platform                platform.Platform
	taskCost                statsd.CloudTaskStatsd
	kubernetesGatherTaskMap map[string]*KubernetesGatherTask
}

// TODO 添加参数
func NewCloud(domain mysql.Domain, cfg config.CloudConfig, ctx context.Context) *Cloud {
	platform, err := platform.NewPlatform(domain, cfg)
	if err != nil {
		log.Error(err)
		return nil
	}

	cCtx, cCancel := context.WithCancel(ctx)
	return &Cloud{
		basicInfo: model.BasicInfo{
			Lcuuid: domain.Lcuuid,
			Name:   domain.Name,
			Type:   domain.Type,
		},
		platform:                platform,
		kubernetesGatherTaskMap: make(map[string]*KubernetesGatherTask),
		cfg:                     cfg,
		cCtx:                    cCtx,
		cCancel:                 cCancel,
		resource: model.Resource{
			ErrorState: common.RESOURCE_STATE_CODE_SUCCESS,
		},
		taskCost: statsd.CloudTaskStatsd{
			TaskCost: make(map[string][]int),
		},
	}
}

func (c *Cloud) Start() {
	go c.run()
	go c.startKubernetesGatherTask()
}

func (c *Cloud) Stop() {
	c.platform.ClearDebugLog()
	if c.cCancel != nil {
		c.cCancel()
	}
}

func (c *Cloud) UpdateBasicInfoName(name string) {
	c.basicInfo.Name = name
}

func (c *Cloud) GetBasicInfo() model.BasicInfo {
	return c.basicInfo
}

func (c *Cloud) GetResource() model.Resource {
	if c.basicInfo.Type != common.KUBERNETES {
		if c.resource.ErrorState != 1 || len(c.resource.VMs) == 0 {
			return model.Resource{
				ErrorState:   c.resource.ErrorState,
				ErrorMessage: c.resource.ErrorMessage,
			}
		}
		c.getSubDomainData()
	}
	c.resource.Verified = true
	c.appendResourceProcess()
	return c.resource
}

func (c *Cloud) GetKubernetesGatherTaskMap() map[string]*KubernetesGatherTask {
	return c.kubernetesGatherTaskMap
}

func (c *Cloud) GetStatter() statsd.StatsdStatter {
	return statsd.StatsdStatter{
		Element: statsd.GetCloudTaskStatsd(c.taskCost),
	}
}

func (c *Cloud) getCloudGatherInterval() int {
	var cloudSyncConfig mysql.SysConfiguration
	if ret := mysql.Db.Where("param_name = ?", "cloud_sync_timer").First(&cloudSyncConfig); ret.Error != nil {
		log.Warning("get cloud_sync_timer failed")
		return int(c.cfg.CloudGatherInterval)
	}
	valueInt, _ := strconv.Atoi(cloudSyncConfig.Value)
	return valueInt
}

func (c *Cloud) getCloudData() {
	if c.basicInfo.Type != common.KUBERNETES {
		var err error
		c.resource, err = c.platform.GetCloudData()
		// 这里因为任务内部没有对成功的状态赋值状态码，在这里统一处理了
		if err != nil {
			c.resource.ErrorMessage = err.Error()
			if c.resource.ErrorState == 0 {
				c.resource.ErrorState = common.RESOURCE_STATE_CODE_EXCEPTION
			}
		} else {
			if c.resource.ErrorState == 0 {
				c.resource.ErrorState = common.RESOURCE_STATE_CODE_SUCCESS
			}
		}
	} else {
		c.getKubernetesData()
	}
	c.appendAddtionalResourcesData()
}

func (c *Cloud) run() {
	log.Infof("cloud (%s) started", c.basicInfo.Name)

	if err := c.platform.CheckAuth(); err != nil {
		log.Errorf("cloud (%+v) check auth failed", c.basicInfo)
	}
	log.Infof("cloud (%s) assemble data starting", c.basicInfo.Name)
	c.getCloudData()
	log.Infof("cloud (%s) assemble data complete", c.basicInfo.Name)

	cloudGatherInterval := c.getCloudGatherInterval()
	ticker := time.NewTicker(time.Second * time.Duration(cloudGatherInterval))
LOOP:
	for {
		select {
		case <-ticker.C:
			c.taskCost.TaskCost = map[string][]int{}
			startTime := time.Now()

			log.Infof("cloud (%s) assemble data starting", c.basicInfo.Name)
			c.getCloudData()
			log.Infof("cloud (%s) assemble data complete", c.basicInfo.Name)

			c.taskCost.TaskCost[c.basicInfo.Lcuuid] = []int{int(time.Now().Sub(startTime).Seconds())}
			statsd.MetaStatsd.RegisterStatsdTable(c)

			// check if cloud sync timer changed
			curCloudGatherInterval := c.getCloudGatherInterval()
			if curCloudGatherInterval != cloudGatherInterval {
				ticker.Stop()
				log.Info("cloud_gather_interval from %d changed to %d", cloudGatherInterval, curCloudGatherInterval)
				cloudGatherInterval = curCloudGatherInterval
				ticker = time.NewTicker(time.Second * time.Duration(cloudGatherInterval))
			}
		case <-c.cCtx.Done():
			break LOOP
		}
	}
	log.Infof("cloud (%s) stopped", c.basicInfo.Name)
	ticker.Stop()
}

func (c *Cloud) startKubernetesGatherTask() {
	log.Infof("cloud (%s) kubernetes gather task started", c.basicInfo.Name)
	c.runKubernetesGatherTask()
	go func() {
		for range time.Tick(time.Duration(c.cfg.KubernetesGatherInterval) * time.Second) {
			c.runKubernetesGatherTask()
		}
	}()
}

func (c *Cloud) runKubernetesGatherTask() {
	if c.basicInfo.Type == common.KUBERNETES {
		// Kubernetes平台，只会有一个KubernetesGatherTask
		// - 如果已存在KubernetesGatherTask，则无需启动新的Task
		// Kubernetes平台，无需考虑KubernetesGatherTask的更新/删除，会在Cloud层面统一处理
		if len(c.kubernetesGatherTaskMap) != 0 {
			return
		}
		var domains []mysql.Domain
		mysql.Db.Where("lcuuid = ?", c.basicInfo.Lcuuid).Find(&domains)
		if len(domains) == 0 {
			return
		}
		domain := domains[0]
		kubernetesGatherTask := NewKubernetesGatherTask(
			&domain, nil, c.cCtx, false, c.cfg.KubernetesGatherInterval,
		)
		if kubernetesGatherTask == nil {
			return
		}
		c.mutex.Lock()
		c.kubernetesGatherTaskMap[domain.Lcuuid] = kubernetesGatherTask
		c.kubernetesGatherTaskMap[domain.Lcuuid].Start()
		c.mutex.Unlock()

	} else {
		// 附属容器集群的处理
		var subDomains []mysql.SubDomain
		var oldSubDomains = mapset.NewSet()
		var newSubDomains = mapset.NewSet()
		var delSubDomains = mapset.NewSet()
		var addSubDomains = mapset.NewSet()
		var intersectSubDomains = mapset.NewSet()

		for lcuuid := range c.kubernetesGatherTaskMap {
			oldSubDomains.Add(lcuuid)
		}

		mysql.Db.Where("domain = ?", c.basicInfo.Lcuuid).Find(&subDomains)
		lcuuidToSubDomain := make(map[string]*mysql.SubDomain)
		for index, subDomain := range subDomains {
			lcuuidToSubDomain[subDomain.Lcuuid] = &subDomains[index]
			newSubDomains.Add(subDomain.Lcuuid)
		}

		// 对于删除的subDomain，停止Task，并移除管理
		delSubDomains = oldSubDomains.Difference(newSubDomains)
		for _, subDomain := range delSubDomains.ToSlice() {
			lcuuid := subDomain.(string)
			c.kubernetesGatherTaskMap[lcuuid].Stop()
			c.mutex.Lock()
			delete(c.kubernetesGatherTaskMap, lcuuid)
			c.mutex.Unlock()
		}

		// 对于新增的subDomain，启动Task，并纳入Manger管理
		addSubDomains = newSubDomains.Difference(oldSubDomains)
		for _, subDomain := range addSubDomains.ToSlice() {
			lcuuid := subDomain.(string)
			kubernetesGatherTask := NewKubernetesGatherTask(
				nil, lcuuidToSubDomain[lcuuid], c.cCtx, true, c.cfg.KubernetesGatherInterval,
			)
			if kubernetesGatherTask == nil {
				continue
			}
			c.mutex.Lock()
			c.kubernetesGatherTaskMap[lcuuid] = kubernetesGatherTask
			c.kubernetesGatherTaskMap[lcuuid].Start()
			c.mutex.Unlock()
		}

		// 检查已有subDomain是否存在配置修改
		// 如果存在配置修改，则停止已有Task，并移除管理；同时启动新的Task，并纳入Cloud管理
		intersectSubDomains = newSubDomains.Intersect(oldSubDomains)
		for _, subDomain := range intersectSubDomains.ToSlice() {
			lcuuid := subDomain.(string)
			oldSubDomain := c.kubernetesGatherTaskMap[lcuuid]
			newSubDomain := lcuuidToSubDomain[lcuuid]
			if oldSubDomain.SubDomainConfig != newSubDomain.Config || oldSubDomain.kubernetesGather.Name != newSubDomain.Name {
				log.Infof("oldSubDomainConfig: %s", oldSubDomain.SubDomainConfig)
				log.Infof("newSubDomainConfig: %s", newSubDomain.Config)
				c.kubernetesGatherTaskMap[lcuuid].Stop()
				kubernetesGatherTask := NewKubernetesGatherTask(
					nil, lcuuidToSubDomain[lcuuid], c.cCtx, true, c.cfg.KubernetesGatherInterval,
				)
				if kubernetesGatherTask == nil {
					continue
				}

				c.mutex.Lock()
				delete(c.kubernetesGatherTaskMap, lcuuid)
				c.kubernetesGatherTaskMap[lcuuid] = kubernetesGatherTask
				c.kubernetesGatherTaskMap[lcuuid].Start()
				c.mutex.Unlock()
			}
		}
	}
}

func (c *Cloud) appendAddtionalResourcesData() {
	var dbItem mysql.DomainAdditionalResource
	result := mysql.Db.Where("domain = ?", c.basicInfo.Lcuuid).Find(&dbItem)
	if result.Error != nil {
		log.Errorf("domain (lcuuid: %s) db query additional resources failed: %s", c.basicInfo.Lcuuid, result.Error.Error())
		return
	} else if result.RowsAffected == 0 {
		log.Debugf("domain (lcuuid: %s) has no additional resources to append", c.basicInfo.Lcuuid)
		return
	}
	var additionalResource model.AdditionalResource
	err := json.Unmarshal([]byte(dbItem.Content), &additionalResource)
	if err != nil {
		log.Errorf("domain (lcuuid: %s) json unmarshal content failed: %s", err.Error())
		return
	}
	c.resource.AZs = append(c.resource.AZs, additionalResource.AZs...)
	c.resource.VPCs = append(c.resource.VPCs, additionalResource.VPCs...)
	c.resource.Networks = append(c.resource.Networks, additionalResource.Subnets...)
	c.resource.Subnets = append(c.resource.Subnets, additionalResource.SubnetCIDRs...)
	c.resource.Hosts = append(c.resource.Hosts, additionalResource.Hosts...)
	c.resource.VMs = append(c.resource.VMs, additionalResource.CHosts...)
	c.resource.VInterfaces = append(c.resource.VInterfaces, additionalResource.VInterfaces...)
	c.resource.IPs = append(c.resource.IPs, additionalResource.IPs...)
	c.appendCloudTags(additionalResource.CHostCloudTags, additionalResource.PodNamespaceCloudTags)
	c.resource.LBs = append(c.resource.LBs, additionalResource.LB...)
	c.resource.LBListeners = append(c.resource.LBListeners, additionalResource.LBListeners...)
	c.resource.LBTargetServers = append(c.resource.LBTargetServers, additionalResource.LBTargetServers...)
}

func (c *Cloud) appendCloudTags(chostCloudTags model.UUIDToCloudTags, podNamespaceCloudTags model.UUIDToCloudTags) {
	for i, chost := range c.resource.VMs {
		if value, ok := chostCloudTags[chost.Lcuuid]; ok {
			c.resource.VMs[i].CloudTags = value
		}
	}
	for i, podNamespace := range c.resource.PodNamespaces {
		if value, ok := podNamespaceCloudTags[podNamespace.Lcuuid]; ok {
			c.resource.PodNamespaces[i].CloudTags = value
		}
	}
}

func (c *Cloud) appendResourceProcess() {

	if genesis.GenesisService == nil {
		log.Error("genesis service is nil")
		return
	}

	genesisSyncData, err := genesis.GenesisService.GetGenesisSyncResponse()
	if err != nil {
		log.Errorf("get genesis sync data failed: %s", err.Error())
		return
	}

	vtapIDToLcuuid, err := common.GetVTapSubDomainMappingByDomain(c.basicInfo.Lcuuid)
	if err != nil {
		log.Errorf("domain (%s) add process failed: %s", c.basicInfo.Name, err.Error())
		return
	}

	for _, sProcess := range genesisSyncData.Processes {
		lcuuid, ok := vtapIDToLcuuid[int(sProcess.VtapID)]
		if !ok {
			continue
		}
		process := model.Process{
			Lcuuid:      sProcess.Lcuuid,
			Name:        sProcess.Name,
			VTapID:      int(sProcess.VtapID),
			PID:         int(sProcess.PID),
			ProcessName: sProcess.ProcessName,
			CommandLine: sProcess.CMDLine,
			UserName:    sProcess.User,
			StartTime:   sProcess.StartTime,
			OSAPPTags:   sProcess.OSAPPTags,
		}
		if lcuuid == "" {
			c.resource.Processes = append(c.resource.Processes, process)
			continue
		}
		subDomainResource, ok := c.resource.SubDomainResources[lcuuid]
		if !ok {
			continue
		}
		process.SubDomainLcuuid = subDomainResource.PodNodes[0].SubDomainLcuuid
		subDomainResource.Processes = append(subDomainResource.Processes, process)
		c.resource.SubDomainResources[lcuuid] = subDomainResource
	}
}
