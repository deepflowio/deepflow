/**
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

package recorder

import (
	"context"
	"time"

	"github.com/op/go-logging"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/listener"
	"github.com/deepflowio/deepflow/server/controller/recorder/updater"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type subDomains struct {
	org *rcommon.ORG

	domainLcuuid string
	domainName   string
	cacheMng     *cache.CacheManager
	eventQueue   *queue.OverwriteQueue

	refreshers map[string]*subDomain
}

func newSubDomains(ctx context.Context, cfg config.RecorderConfig, eventQueue *queue.OverwriteQueue, org *rcommon.ORG, domainLcuuid, domainName string, cacheMng *cache.CacheManager) *subDomains {
	return &subDomains{
		org: org,

		domainLcuuid: domainLcuuid,
		domainName:   domainName,
		cacheMng:     cacheMng,
		eventQueue:   eventQueue,
		refreshers:   make(map[string]*subDomain),
	}
}

func (s *subDomains) RefreshAll(cloudData map[string]cloudmodel.SubDomainResource) error {
	// 遍历 cloud 中的 subdomain 资源，与缓存中的 subdomain 资源对比，根据对比结果增删改
	for lcuuid, resource := range cloudData {
		sd, ok := s.refreshers[lcuuid]
		if !ok {
			sd = s.newRefresher(lcuuid)
			s.refreshers[lcuuid] = sd
		}
		sd.tryRefresh(resource)
	}

	// 遍历 subdomain 字典，删除 cloud 未返回的 subdomain 资源
	for _, sd := range s.refreshers {
		if _, ok := cloudData[sd.Lcuuid]; !ok {
			sd.clear()
		}
	}
	return nil
}

func (s *subDomains) RefreshOne(cloudData map[string]cloudmodel.SubDomainResource) error {
	// 遍历 cloud 中的 subdomain 资源，与缓存中的 subdomain 资源对比，根据对比结果增删改
	for lcuuid, resource := range cloudData {
		sd, ok := s.refreshers[lcuuid]
		if !ok {
			sd = s.newRefresher(lcuuid)
			s.refreshers[lcuuid] = sd
		}
		return sd.tryRefresh(resource)
	}
	return nil
}

func (s *subDomains) newRefresher(lcuuid string) *subDomain {
	copiedOrg := rcommon.ReplaceORGLogger(s.org)
	copiedOrg.Logger.AppendSubDomainLcuuid(lcuuid)
	return newSubDomain(s.eventQueue, copiedOrg, s.domainLcuuid, s.domainName, lcuuid, s.cacheMng.DomainCache.ToolDataSet, s.cacheMng.CreateSubDomainCacheIfNotExists(lcuuid))
}

type subDomain struct {
	org *rcommon.ORG

	domainLcuuid      string
	domainName        string
	domainToolDataSet *tool.DataSet

	Lcuuid     string
	cache      *cache.Cache
	eventQueue *queue.OverwriteQueue
}

func newSubDomain(eventQueue *queue.OverwriteQueue, org *rcommon.ORG, domainLcuuid, domainName, lcuuid string, domainToolDataSet *tool.DataSet, cache *cache.Cache) *subDomain {
	return &subDomain{
		org: org,

		domainLcuuid:      domainLcuuid,
		domainName:        domainName,
		domainToolDataSet: domainToolDataSet,

		Lcuuid:     lcuuid,
		cache:      cache,
		eventQueue: eventQueue,
	}
}

func (s *subDomain) tryRefresh(cloudData cloudmodel.SubDomainResource) error {
	if err := s.shouldRefresh(s.Lcuuid, cloudData); err != nil {
		return err
	}

	select {
	case <-s.cache.RefreshSignal:
		s.cache.IncrementSequence()
		s.cache.SetLogLevel(logging.INFO)

		s.refresh(cloudData)
		s.cache.ResetRefreshSignal(cache.RefreshSignalCallerSubDomain)
	default:
		log.Info(s.org.LogPre("sub_domain refresh is running, does nothing"))
		return RefreshConflictError
	}
	return nil
}

func (s *subDomain) refresh(cloudData cloudmodel.SubDomainResource) {
	log.Info(s.org.LogPre("sub_domain sync refresh started"))

	listener := listener.NewWholeSubDomain(s.domainLcuuid, s.Lcuuid, s.cache, s.eventQueue)
	subDomainUpdatersInUpdateOrder := s.getUpdatersInOrder(cloudData)
	s.executeUpdaters(subDomainUpdatersInUpdateOrder)
	s.notifyOnResourceChanged(subDomainUpdatersInUpdateOrder)
	listener.OnUpdatersCompleted()

	s.updateSyncedAt(s.Lcuuid, cloudData.SyncAt)

	log.Info(s.org.LogPre("sub_domain sync refresh completed"))
}

func (s *subDomain) clear() {
	log.Info(s.org.LogPre("sub_domain clean refresh started"))
	subDomainUpdatersInUpdateOrder := s.getUpdatersInOrder(cloudmodel.SubDomainResource{})
	s.executeUpdaters(subDomainUpdatersInUpdateOrder)
	log.Info(s.org.LogPre("sub_domain clean refresh completed"))
}

func (s *subDomain) shouldRefresh(lcuuid string, cloudData cloudmodel.SubDomainResource) error {
	if cloudData.Verified {
		if len(cloudData.Networks) == 0 || len(cloudData.VInterfaces) == 0 || len(cloudData.Pods) == 0 {
			log.Info(s.org.LogPre("sub_domain has no networks or vinterfaces or pods, does nothing"))
			return DataMissingError
		}
	} else {
		log.Info(s.org.LogPre("sub_domain is not verified, does nothing"))
		return DataNotVerifiedError
	}
	return nil
}

func (s *subDomain) getUpdatersInOrder(cloudData cloudmodel.SubDomainResource) []updater.ResourceUpdater {
	ip := updater.NewIP(s.cache, cloudData.IPs, s.domainToolDataSet)
	ip.GetLANIP().RegisterListener(listener.NewLANIP(s.cache, s.eventQueue))
	ip.GetWANIP().RegisterListener(listener.NewWANIP(s.cache, s.eventQueue))

	return []updater.ResourceUpdater{
		updater.NewPodCluster(s.cache, cloudData.PodClusters).RegisterListener(
			listener.NewPodCluster(s.cache)),
		updater.NewPodNode(s.cache, cloudData.PodNodes).RegisterListener(
			listener.NewPodNode(s.cache, s.eventQueue)),
		updater.NewPodNamespace(s.cache, cloudData.PodNamespaces).RegisterListener(
			listener.NewPodNamespace(s.cache)),
		updater.NewPodIngress(s.cache, cloudData.PodIngresses).RegisterListener(
			listener.NewPodIngress(s.cache)),
		updater.NewPodIngressRule(s.cache, cloudData.PodIngressRules).RegisterListener(
			listener.NewPodIngressRule(s.cache)),
		updater.NewPodService(s.cache, cloudData.PodServices).RegisterListener(
			listener.NewPodService(s.cache, s.eventQueue)),
		updater.NewPodIngressRuleBackend(s.cache, cloudData.PodIngressRuleBackends).RegisterListener(
			listener.NewPodIngressRuleBackend(s.cache)),
		updater.NewPodServicePort(s.cache, cloudData.PodServicePorts).RegisterListener(
			listener.NewPodServicePort(s.cache)),
		updater.NewPodGroup(s.cache, cloudData.PodGroups).RegisterListener(
			listener.NewPodGroup(s.cache)),
		updater.NewPodGroupPort(s.cache, cloudData.PodGroupPorts).RegisterListener(
			listener.NewPodGroupPort(s.cache)),
		updater.NewPodReplicaSet(s.cache, cloudData.PodReplicaSets).RegisterListener(
			listener.NewPodReplicaSet(s.cache)),
		updater.NewPod(s.cache, cloudData.Pods).RegisterListener(
			listener.NewPod(s.cache, s.eventQueue)),
		updater.NewNetwork(s.cache, cloudData.Networks).RegisterListener(
			listener.NewNetwork(s.cache)),
		updater.NewSubnet(s.cache, cloudData.Subnets).RegisterListener(
			listener.NewSubnet(s.cache)),
		updater.NewPrometheusTarget(s.cache, cloudData.PrometheusTargets).RegisterListener(
			listener.NewPrometheusTarget(s.cache)),
		updater.NewVInterface(s.cache, cloudData.VInterfaces, s.domainToolDataSet).RegisterListener(
			listener.NewVInterface(s.cache)),
		ip,
		updater.NewVMPodNodeConnection(s.cache, cloudData.VMPodNodeConnections).RegisterListener( // VMPodNodeConnection需放在最后
			listener.NewVMPodNodeConnection(s.cache)),
		updater.NewProcess(s.cache, cloudData.Processes).RegisterListener(
			listener.NewProcess(s.cache, s.eventQueue)),
	}
}

func (r *subDomain) executeUpdaters(updatersInUpdateOrder []updater.ResourceUpdater) {
	for _, updater := range updatersInUpdateOrder {
		updater.HandleAddAndUpdate()
	}

	// 删除操作的顺序，是创建的逆序
	// 特殊资源：VMPodNodeConnection虽然是末序创建，但需要末序删除，序号-1；
	// 原因：避免数据量大时，此数据删除后，云服务器、容器节点还在，导致采集器类型变化
	processUpdater := updatersInUpdateOrder[len(updatersInUpdateOrder)-1]
	vmPodNodeConnectionUpdater := updatersInUpdateOrder[len(updatersInUpdateOrder)-2]
	// 因为 processUpdater 是 -1，VMPodNodeConnection 是 -2，特殊处理后，逆序删除从 -3 开始
	for i := len(updatersInUpdateOrder) - 3; i >= 0; i-- {
		updatersInUpdateOrder[i].HandleDelete()
	}
	processUpdater.HandleDelete()
	vmPodNodeConnectionUpdater.HandleDelete()
}

func (s *subDomain) notifyOnResourceChanged(updatersInUpdateOrder []updater.ResourceUpdater) {
	platformDataChanged := isPlatformDataChanged(updatersInUpdateOrder)
	if platformDataChanged {
		log.Info(s.org.LogPre("sub domain data changed, refresh platform data"))
		refresh.RefreshCache([]common.DataChanged{common.DATA_CHANGED_PLATFORM_DATA})
	}
}

func (s *subDomain) updateSyncedAt(lcuuid string, syncAt time.Time) {
	if syncAt.IsZero() {
		return
	}
	var subDomain mysql.SubDomain
	err := s.org.DB.Where("lcuuid = ?", lcuuid).First(&subDomain).Error
	if err != nil {
		log.Error(s.org.LogPre("get sub_domain from db failed: %s", err.Error()))
		return
	}
	subDomain.SyncedAt = &syncAt
	s.org.DB.Save(&subDomain)
	log.Debug(s.org.LogPre("update sub_domain (%+v)", subDomain))
}

// TODO 单独刷新 sub_domain 时是否需要更新状态信息
func (s *subDomain) updateStateInfo(cloudData cloudmodel.SubDomainResource) {
	var subDomain mysql.SubDomain
	err := s.org.DB.Where("lcuuid = ?", s.Lcuuid).First(&subDomain).Error
	if err != nil {
		log.Error(s.org.LogPre("get sub_domain from db failed: %s", err.Error()))
		return
	}
	subDomain.State = cloudData.ErrorState
	subDomain.ErrorMsg = cloudData.ErrorMessage
	s.org.DB.Save(&subDomain)
	log.Debug(s.org.LogPre("update sub_domain (%+v)", subDomain))
}
