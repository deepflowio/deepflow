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
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set"
	logging "github.com/op/go-logging"

	"github.com/deepflowys/deepflow/server/controller/cloud/config"
	"github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/cloud/platform"
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/statsd"
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
			c.resource.ErrorState = common.RESOURCE_STATE_CODE_SUCCESS
		}
	} else {
		c.getKubernetesData()
	}
}

func (c *Cloud) run() {
	log.Infof("cloud (%s) started", c.basicInfo.Name)

	if err := c.platform.CheckAuth(); err != nil {
		log.Errorf("cloud (%+v) check auth failed", c.basicInfo)
	}
	log.Infof("cloud (%s) assemble data starting", c.basicInfo.Name)
	c.getCloudData()
	log.Infof("cloud (%s) assemble data complete", c.basicInfo.Name)

	ticker := time.NewTicker(time.Second * time.Duration(c.cfg.CloudGatherInterval))
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
		case <-c.cCtx.Done():
			break LOOP
		}
	}
	log.Infof("cloud (%s) stopped", c.basicInfo.Name)
	ticker.Stop()
}

func (c *Cloud) startKubernetesGatherTask() {
	log.Info("cloud (%s) kubernetes gather task started", c.basicInfo.Name)
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
