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

package recorder

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/op/go-logging"

	cloudmodel "github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	"github.com/deepflowys/deepflow/server/controller/recorder/config"
	"github.com/deepflowys/deepflow/server/controller/recorder/updater"
)

var log = logging.MustGetLogger("recorder")

type Recorder struct {
	cfg          config.RecorderConfig
	ctx          context.Context
	domainLcuuid string
	domainName   string
	cacheMng     *cache.CacheManager
	canRefresh   chan bool // 一个recorder中需要保证，同一时间只有一个goroutine在操作cache
}

func NewRecorder(domainLcuuid string, cfg config.RecorderConfig, ctx context.Context) *Recorder {
	return &Recorder{
		cfg:          cfg,
		ctx:          ctx,
		domainLcuuid: domainLcuuid,
		cacheMng:     cache.NewCacheManager(domainLcuuid),
		canRefresh:   make(chan bool, 1),
	}
}

// recorder 开始，启动一个刷新cache的定时任务，保证cache能够在数据异常后自动恢复
func (r *Recorder) Start() {
	r.canRefresh <- true
	go func() {
		log.Infof("recorder (domain lcuuid: %s) cache refresher started", r.domainLcuuid)
		r.runNewRefreshCache()

		ticker := time.NewTicker(time.Minute * time.Duration(r.cfg.CacheRefreshInterval))
	LOOP:
		for {
			select {
			case <-ticker.C:
				r.runNewRefreshCache()
			case <-r.ctx.Done():
				break LOOP
			}
		}
		log.Infof("recorder (domain lcuuid: %s) cache refresher completed", r.domainLcuuid)
	}()
}

// recorder 同步数据功能入口
func (r *Recorder) Refresh(cloudData cloudmodel.Resource) {
	select {
	// 当前没有未结束的刷新数据goroutine，启动一个同步数据的goroutine
	case <-r.canRefresh:
		r.runNewRefreshWhole(cloudData)

	// 当前有未结束的刷新数据goroutine，记录状态，不启动新的goroutine
	default:
		log.Warningf("last refresh (domain lcuuid: %s) not completed now", r.domainLcuuid)
	}
}

func (r *Recorder) runNewRefreshCache() {
LOOP:
	for {
		select {
		// 当前没有未结束的刷新数据goroutine，启动刷新cache后结束
		case <-r.canRefresh:
			log.Infof("recorder (domain lcuuid: %s) cache refresh started", r.domainLcuuid)
			r.cacheMng.Refresh()
			log.Infof("recorder (domain lcuuid: %s) cache refresh completed", r.domainLcuuid)

			r.canRefresh <- true
			break LOOP

		// 当前有未结束的刷新数据goroutine，等待后再次检查是否可以刷新cache
		default:
			time.Sleep(time.Second * 30)
		}
	}
}

func (r *Recorder) checkCloudData(cloudData cloudmodel.Resource) bool {
	var domain *mysql.Domain
	result := mysql.Db.Where("lcuuid = ?", r.domainLcuuid).First(&domain)
	if result.RowsAffected != int64(1) {
		log.Errorf("db domain (lcuuid: %s) not found", r.domainLcuuid)
		return false
	}
	r.domainName = domain.Name

	if !cloudData.Verified {
		if len(cloudData.Networks) == 0 || len(cloudData.VInterfaces) == 0 {
			log.Infof("domain (lcuuid: %s, name: %s) has no networks or vinterfaces, does nothing", r.domainLcuuid, r.domainName)
			return false
		}
		if len(cloudData.VMs) == 0 && len(cloudData.Pods) == 0 {
			log.Infof("domain (lcuuid: %s, name: %s) has no vms and pods, does nothing", r.domainLcuuid, r.domainName)
			return false
		}
	}
	return true
}

func (r *Recorder) runNewRefreshWhole(cloudData cloudmodel.Resource) {
	go func() {
		// 无论是否会更新资源，需先更新domain及subdomain状态
		r.updateStateInfo(cloudData)

		if !r.checkCloudData(cloudData) {
			r.canRefresh <- true
			return
		}

		log.Infof("recorder (domain lcuuid: %s, name: %s) sync refresh started", r.domainLcuuid, r.domainName)

		r.cacheMng.UpdateSequence()

		r.refreshDomain(cloudData)
		r.refreshSubDomains(cloudData.SubDomainResources)

		r.canRefresh <- true
	}()
}

func (r *Recorder) refreshDomain(cloudData cloudmodel.Resource) {
	log.Infof("domain (lcuuid: %s, name: %s) refresh started", r.domainLcuuid, r.domainName)
	r.updateDomainSyncedAt()

	// 指定创建及更新操作的资源顺序
	// 基本原则：无依赖资源优先；实时性需求高资源优先
	domainUpdatersInUpdateOrder := r.getDomainUpdatersInOrder(cloudData)
	r.executeUpdators(domainUpdatersInUpdateOrder)
	log.Infof("domain (lcuuid: %s, name: %s) refresh completed", r.domainLcuuid, r.domainName)
}

func (r *Recorder) getDomainUpdatersInOrder(cloudData cloudmodel.Resource) []updater.ResourceUpdater {
	return []updater.ResourceUpdater{
		updater.NewRegion(r.cacheMng.DomainCache, cloudData.Regions),
		updater.NewAZ(r.cacheMng.DomainCache, cloudData.AZs),
		updater.NewSubDomain(r.cacheMng.DomainCache, cloudData.SubDomains),
		updater.NewVPC(r.cacheMng.DomainCache, cloudData.VPCs),
		updater.NewHost(r.cacheMng.DomainCache, cloudData.Hosts),
		updater.NewVM(r.cacheMng.DomainCache, cloudData.VMs),
		updater.NewPodCluster(r.cacheMng.DomainCache, cloudData.PodClusters),
		updater.NewPodNode(r.cacheMng.DomainCache, cloudData.PodNodes),
		updater.NewPodNamespace(r.cacheMng.DomainCache, cloudData.PodNamespaces),
		updater.NewPodIngress(r.cacheMng.DomainCache, cloudData.PodIngresses),
		updater.NewPodIngressRule(r.cacheMng.DomainCache, cloudData.PodIngressRules),
		updater.NewPodService(r.cacheMng.DomainCache, cloudData.PodServices),
		updater.NewPodIngressRuleBackend(r.cacheMng.DomainCache, cloudData.PodIngressRuleBackends),
		updater.NewPodServicePort(r.cacheMng.DomainCache, cloudData.PodServicePorts),
		updater.NewPodGroup(r.cacheMng.DomainCache, cloudData.PodGroups),
		updater.NewPodGroupPort(r.cacheMng.DomainCache, cloudData.PodGroupPorts),
		updater.NewPodReplicaSet(r.cacheMng.DomainCache, cloudData.PodReplicaSets),
		updater.NewPod(r.cacheMng.DomainCache, cloudData.Pods),
		updater.NewNetwork(r.cacheMng.DomainCache, cloudData.Networks),
		updater.NewSubnet(r.cacheMng.DomainCache, cloudData.Subnets),
		updater.NewVRouter(r.cacheMng.DomainCache, cloudData.VRouters),
		updater.NewRoutingTable(r.cacheMng.DomainCache, cloudData.RoutingTables),
		updater.NewDHCPPort(r.cacheMng.DomainCache, cloudData.DHCPPorts),
		updater.NewSecurityGroup(r.cacheMng.DomainCache, cloudData.SecurityGroups),
		updater.NewSecurityGroupRule(r.cacheMng.DomainCache, cloudData.SecurityGroupRules),
		updater.NewVMSecurityGroup(r.cacheMng.DomainCache, cloudData.VMSecurityGroups),
		updater.NewNATGateway(r.cacheMng.DomainCache, cloudData.NATGateways),
		updater.NewNATVMConnection(r.cacheMng.DomainCache, cloudData.NATVMConnections),
		updater.NewNATRule(r.cacheMng.DomainCache, cloudData.NATRules),
		updater.NewLB(r.cacheMng.DomainCache, cloudData.LBs),
		updater.NewLBVMConnection(r.cacheMng.DomainCache, cloudData.LBVMConnections),
		updater.NewLBListener(r.cacheMng.DomainCache, cloudData.LBListeners),
		updater.NewLBTargetServer(r.cacheMng.DomainCache, cloudData.LBTargetServers),
		updater.NewRDSInstance(r.cacheMng.DomainCache, cloudData.RDSInstances),
		updater.NewRedisInstance(r.cacheMng.DomainCache, cloudData.RedisInstances),
		updater.NewPeerConnection(r.cacheMng.DomainCache, cloudData.PeerConnections),
		updater.NewCEN(r.cacheMng.DomainCache, cloudData.CENs),
		updater.NewVInterface(r.cacheMng.DomainCache, cloudData.VInterfaces),
		updater.NewFloatingIP(r.cacheMng.DomainCache, cloudData.FloatingIPs),
		updater.NewIP(r.cacheMng.DomainCache, cloudData.IPs),
		updater.NewVMPodNodeConnection(r.cacheMng.DomainCache, cloudData.VMPodNodeConnections), // VMPodNodeConnection需放在最后
	}
}

func (r *Recorder) refreshSubDomains(cloudSubDomainResourceMap map[string]cloudmodel.SubDomainResource) {
	// 遍历cloud中的subdomain资源，与缓存中的subdomain资源对比，根据对比结果增删改
	for subDomainLcuuid, subDomainResource := range cloudSubDomainResourceMap {
		if !subDomainResource.Verified {
			log.Infof("sub_domain (lcuuid: %s) is not verified, does nothing", subDomainLcuuid)
			continue
		}
		log.Infof("sub_domain (lcuuid: %s) sync refresh started", subDomainLcuuid)

		r.updateSubDomainSyncedAt(subDomainLcuuid)

		subDomainUpdatersInUpdateOrder := r.getSubDomainUpdatersInOrder(subDomainLcuuid, subDomainResource, nil)
		r.executeUpdators(subDomainUpdatersInUpdateOrder)

		log.Infof("sub_domain (lcuuid: %s) sync refresh completed", subDomainLcuuid)
	}

	// 遍历缓存中的subdomain cache字典，删除cloud未返回的subdomain资源
	for subDomainLcuuid, subDomainCache := range r.cacheMng.SubDomainCacheMap {
		_, ok := cloudSubDomainResourceMap[subDomainLcuuid]
		if !ok {
			subDomainUpdatersInUpdateOrder := r.getSubDomainUpdatersInOrder(subDomainLcuuid, cloudmodel.SubDomainResource{}, subDomainCache)
			r.executeUpdators(subDomainUpdatersInUpdateOrder)
		}
	}

	log.Infof("recorder (domain lcuuid: %s, name: %s) sync refresh completed", r.domainLcuuid, r.domainName)
}

func (r *Recorder) getSubDomainUpdatersInOrder(subDomainLcuuid string, cloudData cloudmodel.SubDomainResource, subDomainCache *cache.Cache) []updater.ResourceUpdater {
	if subDomainCache == nil {
		subDomainCache = r.cacheMng.CreateSubDomainCacheIfNotExists(subDomainLcuuid)
	}
	return []updater.ResourceUpdater{
		updater.NewPodCluster(subDomainCache, cloudData.PodClusters),
		updater.NewPodNode(subDomainCache, cloudData.PodNodes),
		updater.NewPodNamespace(subDomainCache, cloudData.PodNamespaces),
		updater.NewPodIngress(subDomainCache, cloudData.PodIngresses),
		updater.NewPodIngressRule(subDomainCache, cloudData.PodIngressRules),
		updater.NewPodService(subDomainCache, cloudData.PodServices),
		updater.NewPodIngressRuleBackend(subDomainCache, cloudData.PodIngressRuleBackends),
		updater.NewPodServicePort(subDomainCache, cloudData.PodServicePorts),
		updater.NewPodGroup(subDomainCache, cloudData.PodGroups),
		updater.NewPodGroupPort(subDomainCache, cloudData.PodGroupPorts),
		updater.NewPodReplicaSet(subDomainCache, cloudData.PodReplicaSets),
		updater.NewPod(subDomainCache, cloudData.Pods),
		updater.NewNetwork(subDomainCache, cloudData.Networks),
		updater.NewSubnet(subDomainCache, cloudData.Subnets),
		updater.NewVInterface(subDomainCache, cloudData.VInterfaces),
		updater.NewIP(subDomainCache, cloudData.IPs),
		updater.NewVMPodNodeConnection(subDomainCache, cloudData.VMPodNodeConnections), // VMPodNodeConnection需放在最后
	}
}

func (r *Recorder) executeUpdators(updatersInUpdateOrder []updater.ResourceUpdater) {
	for _, updater := range updatersInUpdateOrder {
		updater.HandleAddAndUpdate()
	}

	// 删除操作的顺序，是创建的逆序
	// 特殊资源：VMPodNodeConnection虽然是末序创建，但需要末序删除，序号-1；
	// 原因：避免数据量大时，此数据删除后，云服务器、容器节点还在，导致采集器类型变化
	vmPodNodeConnectionUpdater := updatersInUpdateOrder[len(updatersInUpdateOrder)-1]
	// 因VMPodNodeConnection是-1，特殊处理后，逆序删除从-2开始
	for i := len(updatersInUpdateOrder) - 2; i >= 0; i-- {
		updatersInUpdateOrder[i].HandleDelete()
	}
	vmPodNodeConnectionUpdater.HandleDelete()
}

func (r *Recorder) formatDomainStateInfo(domainResource cloudmodel.Resource) (state int, errMsg string) {
	// 状态优先级 exception > warning > sunccess
	stateToLevel := map[int]int{
		common.RESOURCE_STATE_CODE_SUCCESS:   1,
		common.RESOURCE_STATE_CODE_WARNING:   2,
		common.RESOURCE_STATE_CODE_EXCEPTION: 3,
	}

	// domain的状态：取云平台自身状态 + 附属容器集群状态中，优先级最高的状态
	// domain的异常信息：取云平台自身异常 + 最多10个附属容器集群异常，剩余附属容器集群异常省略
	state = domainResource.ErrorState
	errMsg = domainResource.ErrorMessage

	var subDomainErrMsgs []string
	for _, subDomainResource := range domainResource.SubDomainResources {
		if stateToLevel[subDomainResource.ErrorState] > stateToLevel[state] {
			state = subDomainResource.ErrorState
		}
		if subDomainResource.ErrorMessage != "" {
			subDomainErrMsgs = append(subDomainErrMsgs, subDomainResource.ErrorMessage)
		}
	}
	subDomainErrNum := len(subDomainErrMsgs)
	if subDomainErrNum != 0 {
		if errMsg != "" {
			errMsg += "\n\n"
		}
		errMsg += fmt.Sprintf("共有%d个附属容器集群存在异常\n", subDomainErrNum)

		var subDomainErrMsgsString string
		if subDomainErrNum > common.SUB_DOMAIN_ERROR_DISPLAY_NUM {
			subDomainErrMsgsString = strings.Join(subDomainErrMsgs[:common.SUB_DOMAIN_ERROR_DISPLAY_NUM], "\n")
			subDomainErrMsgsString += "\n..."
		} else {
			subDomainErrMsgsString = strings.Join(subDomainErrMsgs, "\n")
		}
		errMsg += subDomainErrMsgsString
	}
	return
}

func (r *Recorder) updateStateInfo(cloudData cloudmodel.Resource) {
	var domain mysql.Domain
	err := mysql.Db.Where("lcuuid = ?", r.domainLcuuid).First(&domain).Error
	if err != nil {
		log.Errorf("get domain (lcuuid: %s) from db failed: %s", r.domainLcuuid, err)
		return
	}
	domain.State, domain.ErrorMsg = r.formatDomainStateInfo(cloudData)
	mysql.Db.Save(&domain)

	for subDomainLcuuid, subDomainResource := range cloudData.SubDomainResources {
		var subDomain mysql.SubDomain
		err := mysql.Db.Where("lcuuid = ?", subDomainLcuuid).First(&subDomain).Error
		if err != nil {
			log.Errorf("get sub_domain (lcuuid: %s) from db failed: %s", subDomainLcuuid, err)
			continue
		}
		subDomain.State = subDomainResource.ErrorState
		subDomain.ErrorMsg = subDomainResource.ErrorMessage
		mysql.Db.Save(&subDomain)
	}
}

// TODO 提供db操作接口
func (r *Recorder) updateDomainSyncedAt() {
	var domain mysql.Domain
	err := mysql.Db.Where("lcuuid = ?", r.domainLcuuid).First(&domain).Error
	if err != nil {
		log.Errorf("get domain (lcuuid: %s) from db failed: %s", r.domainLcuuid, err)
		return
	}
	now := time.Now()
	domain.SyncedAt = &now
	mysql.Db.Save(&domain)
}

func (r *Recorder) updateSubDomainSyncedAt(lcuuid string) {
	var subDomain mysql.SubDomain
	err := mysql.Db.Where("lcuuid = ?", lcuuid).First(&subDomain).Error
	if err != nil {
		log.Errorf("get sub_domain (lcuuid: %s) from db failed: %s", lcuuid, err)
		return
	}
	now := time.Now()
	subDomain.SyncedAt = &now
	mysql.Db.Save(&subDomain)
}
