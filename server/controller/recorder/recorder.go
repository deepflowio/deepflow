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

package recorder

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/op/go-logging"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/listener"
	"github.com/deepflowio/deepflow/server/controller/recorder/updater"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

var log = logging.MustGetLogger("recorder")

type Recorder struct {
	cfg          config.RecorderConfig
	ctx          context.Context
	domainLcuuid string
	domainName   string
	cacheMng     *cache.CacheManager
	canRefresh   chan bool // 一个 recorder 中需要保证，同一时间只有一个 goroutine 在操作 cache
	eventQueue   *queue.OverwriteQueue
}

func NewRecorder(domainLcuuid string, cfg config.RecorderConfig, ctx context.Context, eventQueue *queue.OverwriteQueue) *Recorder {
	return &Recorder{
		cfg:          cfg,
		ctx:          ctx,
		domainLcuuid: domainLcuuid,
		cacheMng:     cache.NewCacheManager(domainLcuuid),
		canRefresh:   make(chan bool, 1),
		eventQueue:   eventQueue,
	}
}

// recorder 开始，启动一个刷新 cache 的定时任务，保证 cache 能够在数据异常后自动恢复
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
				r.runNewRefreshCache() // TODO 添加cache与db数据对比，便于发现缓存异常
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
			r.cacheMng.SetLogLevel(logging.DEBUG)
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

func (r *Recorder) shouldRefresh(cloudData cloudmodel.Resource) bool {
	var domain *mysql.Domain
	result := mysql.Db.Where("lcuuid = ?", r.domainLcuuid).First(&domain)
	if result.RowsAffected != int64(1) {
		log.Errorf("db domain (lcuuid: %s) not found", r.domainLcuuid)
		return false
	}
	r.domainName = domain.Name

	if cloudData.Verified {
		if len(cloudData.Networks) == 0 || len(cloudData.VInterfaces) == 0 {
			log.Infof("domain (lcuuid: %s, name: %s) has no networks or vinterfaces, does nothing", r.domainLcuuid, r.domainName)
			return false
		}
		if len(cloudData.VMs) == 0 && len(cloudData.Pods) == 0 {
			log.Infof("domain (lcuuid: %s, name: %s) has no vms and pods, does nothing", r.domainLcuuid, r.domainName)
			return false
		}
	} else {
		log.Infof("domain (lcuuid: %s, name: %s) is not verified, does nothing", r.domainLcuuid, r.domainName)
		return false
	}
	return true
}

func (r *Recorder) runNewRefreshWhole(cloudData cloudmodel.Resource) {
	go func() {
		// 无论是否会更新资源，需先更新domain及subdomain状态
		r.updateStateInfo(cloudData)

		if !r.shouldRefresh(cloudData) {
			r.canRefresh <- true
			return
		}

		log.Infof("recorder (domain lcuuid: %s, name: %s) sync refresh started", r.domainLcuuid, r.domainName)

		r.cacheMng.UpdateSequence()
		r.cacheMng.SetLogLevel(logging.INFO)

		r.refreshDomain(cloudData)
		r.refreshSubDomains(cloudData.SubDomainResources)

		r.canRefresh <- true
	}()
}

func (r *Recorder) refreshDomain(cloudData cloudmodel.Resource) {
	log.Infof("domain (lcuuid: %s, name: %s) refresh started", r.domainLcuuid, r.domainName)

	// 指定创建及更新操作的资源顺序
	// 基本原则：无依赖资源优先；实时性需求高资源优先
	listener := listener.NewWholeDomain(r.domainLcuuid, r.cacheMng.DomainCache, r.eventQueue)
	domainUpdatersInUpdateOrder := r.getDomainUpdatersInOrder(cloudData)
	r.executeUpdaters(domainUpdatersInUpdateOrder)
	r.notifyOnResourceChanged(domainUpdatersInUpdateOrder)
	listener.OnUpdatersCompleted()

	r.updateDomainSyncedAt(cloudData.SyncAt)

	log.Infof("domain (lcuuid: %s, name: %s) refresh completed", r.domainLcuuid, r.domainName)
}

func (r *Recorder) getDomainUpdatersInOrder(cloudData cloudmodel.Resource) []updater.ResourceUpdater {
	ip := updater.NewIP(r.cacheMng.DomainCache, cloudData.IPs, nil)
	ip.GetLANIP().RegisterListener(listener.NewLANIP(r.cacheMng.DomainCache, r.eventQueue))
	ip.GetWANIP().RegisterListener(listener.NewWANIP(r.cacheMng.DomainCache, r.eventQueue))

	return []updater.ResourceUpdater{
		updater.NewRegion(r.cacheMng.DomainCache, cloudData.Regions).RegisterListener(
			listener.NewRegion(r.cacheMng.DomainCache)),
		updater.NewAZ(r.cacheMng.DomainCache, cloudData.AZs).RegisterListener(
			listener.NewAZ(r.cacheMng.DomainCache)),
		updater.NewSubDomain(r.cacheMng.DomainCache, cloudData.SubDomains).RegisterListener(
			listener.NewSubDomain(r.cacheMng.DomainCache)),
		updater.NewVPC(r.cacheMng.DomainCache, cloudData.VPCs).RegisterListener(
			listener.NewVPC(r.cacheMng.DomainCache)),
		updater.NewHost(r.cacheMng.DomainCache, cloudData.Hosts).RegisterListener(
			listener.NewHost(r.cacheMng.DomainCache, r.eventQueue)),
		updater.NewVM(r.cacheMng.DomainCache, cloudData.VMs).RegisterListener(
			listener.NewVM(r.cacheMng.DomainCache, r.eventQueue)),
		updater.NewPodCluster(r.cacheMng.DomainCache, cloudData.PodClusters).RegisterListener(
			listener.NewPodCluster(r.cacheMng.DomainCache)),
		updater.NewPodNode(r.cacheMng.DomainCache, cloudData.PodNodes).RegisterListener(
			listener.NewPodNode(r.cacheMng.DomainCache, r.eventQueue)),
		updater.NewPodNamespace(r.cacheMng.DomainCache, cloudData.PodNamespaces).RegisterListener(
			listener.NewPodNamespace(r.cacheMng.DomainCache)),
		updater.NewPodIngress(r.cacheMng.DomainCache, cloudData.PodIngresses).RegisterListener(
			listener.NewPodIngress(r.cacheMng.DomainCache)),
		updater.NewPodIngressRule(r.cacheMng.DomainCache, cloudData.PodIngressRules).RegisterListener(
			listener.NewPodIngressRule(r.cacheMng.DomainCache)),
		updater.NewPodService(r.cacheMng.DomainCache, cloudData.PodServices).RegisterListener(
			listener.NewPodService(r.cacheMng.DomainCache, r.eventQueue)),
		updater.NewPodIngressRuleBackend(r.cacheMng.DomainCache, cloudData.PodIngressRuleBackends).RegisterListener(
			listener.NewPodIngressRuleBackend(r.cacheMng.DomainCache)),
		updater.NewPodServicePort(r.cacheMng.DomainCache, cloudData.PodServicePorts).RegisterListener(
			listener.NewPodServicePort(r.cacheMng.DomainCache)),
		updater.NewPodGroup(r.cacheMng.DomainCache, cloudData.PodGroups).RegisterListener(
			listener.NewPodGroup(r.cacheMng.DomainCache)),
		updater.NewPodGroupPort(r.cacheMng.DomainCache, cloudData.PodGroupPorts).RegisterListener(
			listener.NewPodGroupPort(r.cacheMng.DomainCache)),
		updater.NewPodReplicaSet(r.cacheMng.DomainCache, cloudData.PodReplicaSets).RegisterListener(
			listener.NewPodReplicaSet(r.cacheMng.DomainCache)),
		updater.NewPod(r.cacheMng.DomainCache, cloudData.Pods).RegisterListener(
			listener.NewPod(r.cacheMng.DomainCache, r.eventQueue)),
		updater.NewPrometheusTarget(r.cacheMng.DomainCache, cloudData.PrometheusTargets).RegisterListener(
			listener.NewPrometheusTarget(r.cacheMng.DomainCache)),
		updater.NewNetwork(r.cacheMng.DomainCache, cloudData.Networks).RegisterListener(
			listener.NewNetwork(r.cacheMng.DomainCache)),
		updater.NewSubnet(r.cacheMng.DomainCache, cloudData.Subnets).RegisterListener(
			listener.NewSubnet(r.cacheMng.DomainCache)),
		updater.NewVRouter(r.cacheMng.DomainCache, cloudData.VRouters).RegisterListener(
			listener.NewVRouter(r.cacheMng.DomainCache, r.eventQueue)),
		updater.NewRoutingTable(r.cacheMng.DomainCache, cloudData.RoutingTables).RegisterListener(
			listener.NewRoutingTable(r.cacheMng.DomainCache)),
		updater.NewDHCPPort(r.cacheMng.DomainCache, cloudData.DHCPPorts).RegisterListener(
			listener.NewDHCPPort(r.cacheMng.DomainCache, r.eventQueue)),
		updater.NewSecurityGroup(r.cacheMng.DomainCache, cloudData.SecurityGroups).RegisterListener(
			listener.NewSecurityGroup(r.cacheMng.DomainCache)),
		updater.NewSecurityGroupRule(r.cacheMng.DomainCache, cloudData.SecurityGroupRules).RegisterListener(
			listener.NewSecurityGroupRule(r.cacheMng.DomainCache)),
		updater.NewVMSecurityGroup(r.cacheMng.DomainCache, cloudData.VMSecurityGroups).RegisterListener(
			listener.NewVMSecurityGroup(r.cacheMng.DomainCache)),
		updater.NewNATGateway(r.cacheMng.DomainCache, cloudData.NATGateways).RegisterListener(
			listener.NewNATGateway(r.cacheMng.DomainCache, r.eventQueue)),
		updater.NewNATVMConnection(r.cacheMng.DomainCache, cloudData.NATVMConnections).RegisterListener(
			listener.NewNATVMConnection(r.cacheMng.DomainCache)),
		updater.NewNATRule(r.cacheMng.DomainCache, cloudData.NATRules).RegisterListener(
			listener.NewNATRule(r.cacheMng.DomainCache)),
		updater.NewLB(r.cacheMng.DomainCache, cloudData.LBs).RegisterListener(
			listener.NewLB(r.cacheMng.DomainCache, r.eventQueue)),
		updater.NewLBVMConnection(r.cacheMng.DomainCache, cloudData.LBVMConnections).RegisterListener(
			listener.NewLBVMConnection(r.cacheMng.DomainCache)),
		updater.NewLBListener(r.cacheMng.DomainCache, cloudData.LBListeners).RegisterListener(
			listener.NewLBListener(r.cacheMng.DomainCache)),
		updater.NewLBTargetServer(r.cacheMng.DomainCache, cloudData.LBTargetServers).RegisterListener(
			listener.NewLBTargetServer(r.cacheMng.DomainCache)),
		updater.NewRDSInstance(r.cacheMng.DomainCache, cloudData.RDSInstances).RegisterListener(
			listener.NewRDSInstance(r.cacheMng.DomainCache, r.eventQueue)),
		updater.NewRedisInstance(r.cacheMng.DomainCache, cloudData.RedisInstances).RegisterListener(
			listener.NewRedisInstance(r.cacheMng.DomainCache, r.eventQueue)),
		updater.NewPeerConnection(r.cacheMng.DomainCache, cloudData.PeerConnections).RegisterListener(
			listener.NewPeerConnection(r.cacheMng.DomainCache)),
		updater.NewCEN(r.cacheMng.DomainCache, cloudData.CENs).RegisterListener(
			listener.NewCEN(r.cacheMng.DomainCache)),
		updater.NewVInterface(r.cacheMng.DomainCache, cloudData.VInterfaces, nil).RegisterListener(
			listener.NewVInterface(r.cacheMng.DomainCache)),
		updater.NewFloatingIP(r.cacheMng.DomainCache, cloudData.FloatingIPs).RegisterListener(
			listener.NewFloatingIP(r.cacheMng.DomainCache)),
		ip,
		updater.NewVIP(r.cacheMng.DomainCache, cloudData.VIPs).RegisterListener(
			listener.NewVIP(r.cacheMng.DomainCache)),
		updater.NewVMPodNodeConnection(r.cacheMng.DomainCache, cloudData.VMPodNodeConnections).RegisterListener( // VMPodNodeConnection需放在最后
			listener.NewVMPodNodeConnection(r.cacheMng.DomainCache)),
		updater.NewProcess(r.cacheMng.DomainCache, cloudData.Processes).RegisterListener(
			listener.NewProcess(r.cacheMng.DomainCache, r.eventQueue)),
	}
}

func (r *Recorder) shouldRefreshSubDomain(lcuuid string, cloudData cloudmodel.SubDomainResource) bool {
	if cloudData.Verified {
		if len(cloudData.Networks) == 0 || len(cloudData.VInterfaces) == 0 || len(cloudData.Pods) == 0 {
			log.Infof("sub_domain (lcuuid: %s, name: %s) has no networks or vinterfaces or pods, does nothing", lcuuid)
			return false
		}
	} else {
		log.Infof("sub_domain (lcuuid: %s) is not verified, does nothing", lcuuid)
		return false
	}
	return true
}

func (r *Recorder) refreshSubDomains(cloudSubDomainResourceMap map[string]cloudmodel.SubDomainResource) {
	// 遍历cloud中的subdomain资源，与缓存中的subdomain资源对比，根据对比结果增删改
	for subDomainLcuuid, subDomainResource := range cloudSubDomainResourceMap {
		if !r.shouldRefreshSubDomain(subDomainLcuuid, subDomainResource) {
			continue
		}
		log.Infof("sub_domain (lcuuid: %s) sync refresh started", subDomainLcuuid)

		listener := listener.NewWholeSubDomain(r.domainLcuuid, subDomainLcuuid, r.cacheMng.DomainCache, r.eventQueue)
		subDomainUpdatersInUpdateOrder := r.getSubDomainUpdatersInOrder(subDomainLcuuid, subDomainResource, nil, nil)
		r.executeUpdaters(subDomainUpdatersInUpdateOrder)
		r.notifyOnResourceChanged(subDomainUpdatersInUpdateOrder)
		listener.OnUpdatersCompleted()

		r.updateSubDomainSyncedAt(subDomainLcuuid, subDomainResource.SyncAt)

		log.Infof("sub_domain (lcuuid: %s) sync refresh completed", subDomainLcuuid)
	}

	// 遍历缓存中的subdomain cache字典，删除cloud未返回的subdomain资源
	for subDomainLcuuid, subDomainCache := range r.cacheMng.SubDomainCacheMap {
		_, ok := cloudSubDomainResourceMap[subDomainLcuuid]
		if !ok {
			log.Infof("sub_domain (lcuuid: %s) clean refresh started", subDomainLcuuid)
			subDomainUpdatersInUpdateOrder := r.getSubDomainUpdatersInOrder(subDomainLcuuid, cloudmodel.SubDomainResource{}, subDomainCache, &r.cacheMng.DomainCache.ToolDataSet)
			r.executeUpdaters(subDomainUpdatersInUpdateOrder)
			log.Infof("sub_domain (lcuuid: %s) clean refresh completed", subDomainLcuuid)
		}
	}
}

func (r *Recorder) getSubDomainUpdatersInOrder(subDomainLcuuid string, cloudData cloudmodel.SubDomainResource,
	subDomainCache *cache.Cache, domainToolDataSet *cache.ToolDataSet) []updater.ResourceUpdater {
	if subDomainCache == nil {
		subDomainCache = r.cacheMng.CreateSubDomainCacheIfNotExists(subDomainLcuuid)
	}

	ip := updater.NewIP(subDomainCache, cloudData.IPs, domainToolDataSet)
	ip.GetLANIP().RegisterListener(listener.NewLANIP(subDomainCache, r.eventQueue))
	ip.GetWANIP().RegisterListener(listener.NewWANIP(subDomainCache, r.eventQueue))

	return []updater.ResourceUpdater{
		updater.NewPodCluster(subDomainCache, cloudData.PodClusters).RegisterListener(
			listener.NewPodCluster(subDomainCache)),
		updater.NewPodNode(subDomainCache, cloudData.PodNodes).RegisterListener(
			listener.NewPodNode(subDomainCache, r.eventQueue)),
		updater.NewPodNamespace(subDomainCache, cloudData.PodNamespaces).RegisterListener(
			listener.NewPodNamespace(subDomainCache)),
		updater.NewPodIngress(subDomainCache, cloudData.PodIngresses).RegisterListener(
			listener.NewPodIngress(subDomainCache)),
		updater.NewPodIngressRule(subDomainCache, cloudData.PodIngressRules).RegisterListener(
			listener.NewPodIngressRule(subDomainCache)),
		updater.NewPodService(subDomainCache, cloudData.PodServices).RegisterListener(
			listener.NewPodService(subDomainCache, r.eventQueue)),
		updater.NewPodIngressRuleBackend(subDomainCache, cloudData.PodIngressRuleBackends).RegisterListener(
			listener.NewPodIngressRuleBackend(subDomainCache)),
		updater.NewPodServicePort(subDomainCache, cloudData.PodServicePorts).RegisterListener(
			listener.NewPodServicePort(subDomainCache)),
		updater.NewPodGroup(subDomainCache, cloudData.PodGroups).RegisterListener(
			listener.NewPodGroup(subDomainCache)),
		updater.NewPodGroupPort(subDomainCache, cloudData.PodGroupPorts).RegisterListener(
			listener.NewPodGroupPort(subDomainCache)),
		updater.NewPodReplicaSet(subDomainCache, cloudData.PodReplicaSets).RegisterListener(
			listener.NewPodReplicaSet(subDomainCache)),
		updater.NewPod(subDomainCache, cloudData.Pods).RegisterListener(
			listener.NewPod(subDomainCache, r.eventQueue)),
		updater.NewNetwork(subDomainCache, cloudData.Networks).RegisterListener(
			listener.NewNetwork(subDomainCache)),
		updater.NewSubnet(subDomainCache, cloudData.Subnets).RegisterListener(
			listener.NewSubnet(subDomainCache)),
		updater.NewPrometheusTarget(subDomainCache, cloudData.PrometheusTargets).RegisterListener(
			listener.NewPrometheusTarget(subDomainCache)),
		updater.NewVInterface(subDomainCache, cloudData.VInterfaces, domainToolDataSet).RegisterListener(
			listener.NewVInterface(subDomainCache)),
		ip,
		updater.NewVMPodNodeConnection(subDomainCache, cloudData.VMPodNodeConnections).RegisterListener( // VMPodNodeConnection需放在最后
			listener.NewVMPodNodeConnection(subDomainCache)),
		updater.NewProcess(subDomainCache, cloudData.Processes).RegisterListener(
			listener.NewProcess(subDomainCache, r.eventQueue)),
	}
}

func (r *Recorder) executeUpdaters(updatersInUpdateOrder []updater.ResourceUpdater) {
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

func (r *Recorder) notifyOnResourceChanged(updatersInUpdateOrder []updater.ResourceUpdater) {
	platformDataChanged := isPlatformDataChanged(updatersInUpdateOrder)
	if platformDataChanged {
		log.Infof("domain(%v) data changed, refresh platform data", r.domainLcuuid)
		refresh.RefreshCache([]common.DataChanged{common.DATA_CHANGED_PLATFORM_DATA})
	}
}

var platformDataResource = []string{
	"mysql.Region", "mysql.AZ", "mysql.Host", "mysql.VM", "mysql.VInterface",
	"mysql.VRouter", "mysql.Network", "mysql.PeerConnection",
	"mysql.Pod", "mysql.PodNode", "mysql.Process",
}

func isPlatformDataChanged(updatersInUpdateOrder []updater.ResourceUpdater) bool {
	platformDataChanged := false
	for _, updater := range updatersInUpdateOrder {
		for _, resource := range updater.GetMySQLModelString() {
			if common.Contains(platformDataResource, resource) {
				platformDataChanged = platformDataChanged || updater.GetChanged()
			}
		}
	}
	return platformDataChanged
}

func (r *Recorder) formatDomainStateInfo(domainResource cloudmodel.Resource) (state int, errMsg string) {
	log.Infof("cloud domain (%s) state info: %d, %s", r.domainName, domainResource.ErrorState, domainResource.ErrorMessage)
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
	for subDomainLcuuid, subDomainResource := range domainResource.SubDomainResources {
		log.Infof("cloud sub_domain (%s) state info: %d, %s", subDomainLcuuid, subDomainResource.ErrorState, subDomainResource.ErrorMessage)
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
	log.Debugf("update domain (%+v)", domain)

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
		log.Debugf("update sub_domain (%+v)", subDomain)
	}
}

// TODO 提供db操作接口
func (r *Recorder) updateDomainSyncedAt(syncAt time.Time) {
	if syncAt.IsZero() {
		return
	}
	var domain mysql.Domain
	err := mysql.Db.Where("lcuuid = ?", r.domainLcuuid).First(&domain).Error
	if err != nil {
		log.Errorf("get domain (lcuuid: %s) from db failed: %s", r.domainLcuuid, err)
		return
	}
	domain.SyncedAt = &syncAt
	mysql.Db.Save(&domain)
	log.Debugf("update domain (%+v)", domain)
}

func (r *Recorder) updateSubDomainSyncedAt(lcuuid string, syncAt time.Time) {
	if syncAt.IsZero() {
		return
	}
	var subDomain mysql.SubDomain
	err := mysql.Db.Where("lcuuid = ?", lcuuid).First(&subDomain).Error
	if err != nil {
		log.Errorf("get sub_domain (lcuuid: %s) from db failed: %s", lcuuid, err)
		return
	}
	subDomain.SyncedAt = &syncAt
	mysql.Db.Save(&subDomain)
	log.Debugf("update sub_domain (%+v)", subDomain)
}
