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

package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/bitly/go-simplejson"
	mapset "github.com/deckarep/golang-set"
	logging "github.com/op/go-logging"
	"gorm.io/gorm"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
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

	log.Infof("cloud task (%s) init success", domain.Name)

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
			TaskCost: make(map[string][]float64),
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
	cResource := c.resource
	if c.basicInfo.Type != common.KUBERNETES {
		if cResource.ErrorState == common.RESOURCE_STATE_CODE_SUCCESS && cResource.Verified && len(cResource.VMs) > 0 {
			cResource.SubDomainResources = c.getSubDomainData(cResource)
			cResource = c.appendResourceVIPs(cResource)
		}
	}

	if cResource.Verified {
		cResource = c.appendAddtionalResourcesData(cResource)
		cResource = c.appendResourceProcess(cResource)
	}
	return cResource
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
	var domain mysql.Domain
	err := mysql.Db.Where("lcuuid = ?", c.basicInfo.Lcuuid).First(&domain).Error
	if err != nil {
		log.Warningf("get cloud gather interval failed: (%s)", err.Error())
		return cloudcommon.CLOUD_SYNC_TIMER_MIN
	}
	domainConfig, err := simplejson.NewJson([]byte(domain.Config))
	if err != nil {
		log.Warningf("parse domain (%s) config failed: (%s)", c.basicInfo.Name, err.Error())
		return cloudcommon.CLOUD_SYNC_TIMER_MIN
	}
	domainSyncTimer := domainConfig.Get("sync_timer").MustInt()
	if domainSyncTimer == 0 {
		return cloudcommon.CLOUD_SYNC_TIMER_MIN
	}
	if domainSyncTimer < cloudcommon.CLOUD_SYNC_TIMER_MIN || domainSyncTimer > cloudcommon.CLOUD_SYNC_TIMER_MAX {
		log.Warningf("cloud sync timer invalid: (%d)", domainSyncTimer)
		return cloudcommon.CLOUD_SYNC_TIMER_MIN
	}
	return domainSyncTimer
}

func (c *Cloud) getCloudData() {
	var cResource model.Resource
	var cloudCost float64
	if c.basicInfo.Type != common.KUBERNETES {
		var err error
		startTime := time.Now()
		cResource, err = c.platform.GetCloudData()
		cloudCost = time.Now().Sub(startTime).Seconds()
		// 这里因为任务内部没有对成功的状态赋值状态码，在这里统一处理了
		if err == nil {
			if cResource.ErrorState == 0 {
				cResource.Verified = true
				cResource.ErrorState = common.RESOURCE_STATE_CODE_SUCCESS
			}
		} else {
			if cResource.ErrorState == 0 {
				cResource.ErrorState = common.RESOURCE_STATE_CODE_EXCEPTION
			}
			cResource = model.Resource{
				ErrorMessage: err.Error(),
				ErrorState:   cResource.ErrorState,
			}
		}
	} else {
		cResource, cloudCost = c.getKubernetesData()
	}

	if len(cResource.VMs) == 0 {
		cResource = model.Resource{
			ErrorState:   cResource.ErrorState,
			ErrorMessage: cResource.ErrorMessage,
		}
	}

	cResource.SyncAt = time.Now()
	c.resource = cResource
	c.sendStatsd(cloudCost)
}

func (c *Cloud) sendStatsd(cloudCost float64) {
	c.taskCost.TaskCost = map[string][]float64{
		c.basicInfo.Lcuuid: []float64{cloudCost},
	}
	statsd.MetaStatsd.RegisterStatsdTable(c)
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
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Infof("cloud (%s) assemble data starting", c.basicInfo.Name)
			c.getCloudData()
			log.Infof("cloud (%s) assemble data complete", c.basicInfo.Name)
		case <-c.cCtx.Done():
			log.Infof("cloud (%s) stopped", c.basicInfo.Name)
			return
		}
	}
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
	var domain mysql.Domain
	err := mysql.Db.Where("lcuuid = ?", c.basicInfo.Lcuuid).First(&domain).Error
	if err != nil {
		log.Error(err)
		return
	}

	if c.basicInfo.Type == common.KUBERNETES {
		// Kubernetes平台，只会有一个KubernetesGatherTask
		// - 如果已存在KubernetesGatherTask，则无需启动新的Task
		// Kubernetes平台，无需考虑KubernetesGatherTask的更新/删除，会在Cloud层面统一处理
		if len(c.kubernetesGatherTaskMap) != 0 {
			return
		}
		kubernetesGatherTask := NewKubernetesGatherTask(c.cCtx, &domain, nil, c.cfg, false)
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
			kubernetesGatherTask := NewKubernetesGatherTask(c.cCtx, &domain, lcuuidToSubDomain[lcuuid], c.cfg, true)
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
				kubernetesGatherTask := NewKubernetesGatherTask(c.cCtx, &domain, lcuuidToSubDomain[lcuuid], c.cfg, true)
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

func (c *Cloud) appendAddtionalResourcesData(resource model.Resource) model.Resource {
	dbItem, err := getContentFromAdditionalResource(c.basicInfo.Lcuuid)
	if err != nil {
		log.Errorf("domain (lcuuid: %s) get additional resources failed: %s", c.basicInfo.Lcuuid, err)
		return resource
	}
	if dbItem == nil {
		log.Debugf("domain (lcuuid: %s) has no additional resources to append", c.basicInfo.Lcuuid)
		return resource
	}

	content := dbItem.CompressedContent
	if len(dbItem.CompressedContent) == 0 {
		content = []byte(dbItem.Content)
	}
	var additionalResource model.AdditionalResource
	if err = json.Unmarshal(content, &additionalResource); err != nil {
		log.Errorf("domain (lcuuid: %s) json unmarshal content failed: %s", c.basicInfo.Lcuuid, err.Error())
		return resource
	}

	resource.AZs = append(resource.AZs, additionalResource.AZs...)
	resource.VPCs = append(resource.VPCs, additionalResource.VPCs...)
	resource.Networks = append(resource.Networks, additionalResource.Subnets...)
	resource.Subnets = append(resource.Subnets, additionalResource.SubnetCIDRs...)
	resource.Hosts = append(resource.Hosts, additionalResource.Hosts...)
	resource.VMs = append(resource.VMs, additionalResource.CHosts...)
	resource.VInterfaces = append(resource.VInterfaces, additionalResource.VInterfaces...)
	resource.IPs = append(resource.IPs, additionalResource.IPs...)
	resource = c.appendCloudTags(resource, additionalResource)
	resource.LBs = append(resource.LBs, additionalResource.LB...)
	resource.LBListeners = append(resource.LBListeners, additionalResource.LBListeners...)
	resource.LBTargetServers = append(resource.LBTargetServers, additionalResource.LBTargetServers...)
	resource.PeerConnections = append(resource.PeerConnections, additionalResource.PeerConnections...)
	return resource
}

// getContentFromAdditionalResource gets domain_additional_resource by uuid, get the field content if it exists,
// otherwise get the field compressed_content.
// old content field: content
// new centent field: compressed_content
func getContentFromAdditionalResource(domainUUID string) (*mysql.DomainAdditionalResource, error) {
	var dbItem mysql.DomainAdditionalResource
	result := mysql.Db.Select("content").Where("domain = ? and content!=''", domainUUID).First(&dbItem)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		result = mysql.Db.Select("compressed_content").Where("domain = ?", domainUUID).First(&dbItem)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
	}

	if result.RowsAffected != 0 {
		return &dbItem, nil
	}
	if result.Error != nil {
		return nil, result.Error
	}
	return &dbItem, nil
}

func (c *Cloud) appendCloudTags(resource model.Resource, additionalResource model.AdditionalResource) model.Resource {
	chostCloudTags := additionalResource.CHostCloudTags
	for i, chost := range resource.VMs {
		value, ok := chostCloudTags[chost.Lcuuid]
		if !ok {
			continue
		}
		if len(chost.CloudTags) != 0 {
			log.Infof("vm (%s) already tags (%v), do not need to add (%v)", chost.Name, chost.CloudTags, value)
			continue
		}
		resource.VMs[i].CloudTags = value
	}
	podNamespaceCloudTags := additionalResource.PodNamespaceCloudTags
	for i, podNamespace := range resource.PodNamespaces {
		if value, ok := podNamespaceCloudTags[podNamespace.Lcuuid]; ok {
			resource.PodNamespaces[i].CloudTags = value
		}
	}

	additionalSubdomainResources := additionalResource.SubDomainResources
	for subdomainUUID, subdomainResource := range resource.SubDomainResources {
		additionalSubdomainResource, ok := additionalSubdomainResources[subdomainUUID]
		if !ok {
			continue
		}
		for i, podNamespace := range subdomainResource.PodNamespaces {
			if additionalSubdomainResource.PodNamespaceCloudTags != nil {
				if value, ok := additionalSubdomainResource.PodNamespaceCloudTags[podNamespace.Lcuuid]; ok {
					subdomainResource.PodNamespaces[i].CloudTags = value
				}
			}
		}
	}
	return resource
}

func (c *Cloud) appendResourceProcess(resource model.Resource) model.Resource {

	if genesis.GenesisService == nil {
		log.Error("genesis service is nil")
		return resource
	}

	genesisSyncData, err := genesis.GenesisService.GetGenesisSyncResponse()
	if err != nil {
		log.Error(err.Error())
		return resource
	}

	vtapIDToLcuuid, err := cloudcommon.GetVTapSubDomainMappingByDomain(c.basicInfo.Lcuuid)
	if err != nil {
		log.Errorf("domain (%s) add process failed: %s", c.basicInfo.Name, err.Error())
		return resource
	}

	for _, sProcess := range genesisSyncData.Processes {
		lcuuid, ok := vtapIDToLcuuid[int(sProcess.VtapID)]
		if !ok {
			continue
		}
		name, processName := sProcess.Name, sProcess.ProcessName
		if len(sProcess.Name) > c.cfg.ProcessNameLenMax {
			name = sProcess.Name[:c.cfg.ProcessNameLenMax]
		}
		if len(sProcess.ProcessName) > c.cfg.ProcessNameLenMax {
			processName = sProcess.ProcessName[:c.cfg.ProcessNameLenMax]
		}
		process := model.Process{
			Lcuuid:      sProcess.Lcuuid,
			Name:        name,
			VTapID:      sProcess.VtapID,
			PID:         sProcess.PID,
			NetnsID:     sProcess.NetnsID,
			ProcessName: processName,
			CommandLine: sProcess.CMDLine,
			UserName:    sProcess.User,
			ContainerID: sProcess.ContainerID,
			StartTime:   sProcess.StartTime,
			OSAPPTags:   sProcess.OSAPPTags,
		}
		if lcuuid == "" {
			resource.Processes = append(resource.Processes, process)
			continue
		}
		subDomainResource, ok := resource.SubDomainResources[lcuuid]
		if !ok || !subDomainResource.Verified {
			continue
		}
		process.SubDomainLcuuid = lcuuid
		subDomainResource.Processes = append(subDomainResource.Processes, process)
		resource.SubDomainResources[lcuuid] = subDomainResource
	}
	return resource
}

func (c *Cloud) appendResourceVIPs(resource model.Resource) model.Resource {

	if genesis.GenesisService == nil {
		log.Error("genesis service is nil")
		return resource
	}

	genesisSyncData, err := genesis.GenesisService.GetGenesisSyncResponse()
	if err != nil {
		log.Error(err.Error())
		return resource
	}

	vtapIDToLcuuid, err := cloudcommon.GetVTapSubDomainMappingByDomain(c.basicInfo.Lcuuid)
	if err != nil {
		log.Errorf("domain (%s) add vip failed: %s", c.basicInfo.Name, err.Error())
		return resource
	}

	for _, vip := range genesisSyncData.VIPs {
		lcuuid, ok := vtapIDToLcuuid[int(vip.VtapID)]
		if !ok || lcuuid != "" {
			continue
		}
		resource.VIPs = append(resource.VIPs, model.VIP{
			Lcuuid: vip.Lcuuid,
			IP:     vip.IP,
			VTapID: vip.VtapID,
		})
	}
	return resource
}
