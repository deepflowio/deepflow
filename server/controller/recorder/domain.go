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
	"errors"
	"fmt"
	"strings"
	"time"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/listener"
	"github.com/deepflowio/deepflow/server/controller/recorder/updater"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/op/go-logging"
)

const (
	RefreshTargetDomain = iota
	// RefreshTargetDomainExcludeSubDomain
	RefreshTargetSubDomain
)

type domain struct {
	eventQueue *queue.OverwriteQueue

	domainLcuuid string
	domainName   string
	cache        *cache.Cache

	subDomains *subDomains
}

func newDomain(ctx context.Context, cfg config.RecorderConfig, eventQueue *queue.OverwriteQueue, domainLcuuid, domainName string) *domain {
	cacheMng := cache.NewCacheManager(ctx, cfg, domainLcuuid)
	return &domain{
		eventQueue: eventQueue,

		domainLcuuid: domainLcuuid,
		domainName:   domainName,
		cache:        cacheMng.DomainCache,

		subDomains: newSubDomains(ctx, cfg, eventQueue, domainLcuuid, domainName, cacheMng),
	}
}

func (d *domain) Refresh(target int, cloudData cloudmodel.Resource) error {

	switch target {
	case RefreshTargetDomain:
		log.Infof("domain: %s refresher started, triggered by ticker/hand", d.domainName)
		if err := d.refreshDomainExcludeSubDomain(cloudData); err != nil {
			return err
		}
		return d.subDomains.RefreshAll(cloudData.SubDomainResources)
	// case RefreshTargetDomainExcludeSubDomain:
	// 	return d.refreshDomainExcludeSubDomain(cloudData)
	case RefreshTargetSubDomain:
		log.Infof("domain: %s refresher started, triggered by hand", d.domainName)
		return d.subDomains.RefreshOne(cloudData.SubDomainResources)
	default:
		return errors.New("invalid refresh target")
	}
}

func (d *domain) refreshDomainExcludeSubDomain(cloudData cloudmodel.Resource) error {
	log.Info("in refreshDomainExcludeSubDomain")
	return d.tryRefresh(cloudData)
}

func (r *domain) tryRefresh(cloudData cloudmodel.Resource) error {
	// 无论是否会更新资源，需先更新domain及subdomain状态
	r.updateStateInfo(cloudData)

	if err := r.shouldRefresh(cloudData); err != nil {
		return err
	}

	select {
	case <-r.cache.RefreshSignal:
		r.cache.IncrementSequence()
		r.cache.SetLogLevel(logging.INFO)

		r.refresh(cloudData)

		r.cache.ResetRefreshSignal(cache.RefreshSignalCallerDomain)
		return nil
	default:
		log.Infof("domain (lcuuid: %s) refresh is running, does nothing", r.domainLcuuid)
		return RefreshConflictError
	}
}

func (d *domain) shouldRefresh(cloudData cloudmodel.Resource) error {
	var domain *mysql.Domain
	result := mysql.Db.Where("lcuuid = ?", d.domainLcuuid).First(&domain)
	if result.RowsAffected != int64(1) {
		err := errors.New(fmt.Sprintf("db domain (lcuuid: %s) not found", d.domainLcuuid))
		log.Errorf(err.Error())
		return err
	}
	d.domainName = domain.Name

	if cloudData.Verified {
		if len(cloudData.Networks) == 0 || len(cloudData.VInterfaces) == 0 {
			log.Infof("domain (lcuuid: %s, name: %s) has no networks or vinterfaces, does nothing", d.domainLcuuid, d.domainName)
			return DataMissingError
		}
		if len(cloudData.VMs) == 0 && len(cloudData.Pods) == 0 {
			log.Infof("domain (lcuuid: %s, name: %s) has no vms and pods, does nothing", d.domainLcuuid, d.domainName)
			return DataMissingError
		}
	} else {
		log.Infof("domain (lcuuid: %s, name: %s) is not verified, does nothing", d.domainLcuuid, d.domainName)
		return DataNotVerifiedError
	}
	return nil
}

func (d *domain) refresh(cloudData cloudmodel.Resource) {
	log.Infof("domain (lcuuid: %s, name: %s) refresh started", d.domainLcuuid, d.domainName)

	// 指定创建及更新操作的资源顺序
	// 基本原则：无依赖资源优先；实时性需求高资源优先
	listener := listener.NewWholeDomain(d.domainLcuuid, d.cache, d.eventQueue)
	domainUpdatersInUpdateOrder := d.getUpdatersInOrder(cloudData)
	d.executeUpdaters(domainUpdatersInUpdateOrder)
	d.notifyOnResourceChanged(domainUpdatersInUpdateOrder)
	listener.OnUpdatersCompleted()

	d.updateSyncedAt(cloudData.SyncAt)

	log.Infof("domain (lcuuid: %s, name: %s) refresh completed", d.domainLcuuid, d.domainName)
}

func (d *domain) getUpdatersInOrder(cloudData cloudmodel.Resource) []updater.ResourceUpdater {
	ip := updater.NewIP(d.cache, cloudData.IPs, nil)
	ip.GetLANIP().RegisterListener(listener.NewLANIP(d.cache, d.eventQueue))
	ip.GetWANIP().RegisterListener(listener.NewWANIP(d.cache, d.eventQueue))

	return []updater.ResourceUpdater{
		updater.NewRegion(d.cache, cloudData.Regions).RegisterListener(
			listener.NewRegion(d.cache)),
		updater.NewAZ(d.cache, cloudData.AZs).RegisterListener(
			listener.NewAZ(d.cache)),
		updater.NewSubDomain(d.cache, cloudData.SubDomains).RegisterListener(
			listener.NewSubDomain(d.cache)),
		updater.NewVPC(d.cache, cloudData.VPCs).RegisterListener(
			listener.NewVPC(d.cache)),
		updater.NewHost(d.cache, cloudData.Hosts).RegisterListener(
			listener.NewHost(d.cache, d.eventQueue)),
		updater.NewVM(d.cache, cloudData.VMs).RegisterListener(
			listener.NewVM(d.cache, d.eventQueue)),
		updater.NewPodCluster(d.cache, cloudData.PodClusters).RegisterListener(
			listener.NewPodCluster(d.cache)),
		updater.NewPodNode(d.cache, cloudData.PodNodes).RegisterListener(
			listener.NewPodNode(d.cache, d.eventQueue)),
		updater.NewPodNamespace(d.cache, cloudData.PodNamespaces).RegisterListener(
			listener.NewPodNamespace(d.cache)),
		updater.NewPodIngress(d.cache, cloudData.PodIngresses).RegisterListener(
			listener.NewPodIngress(d.cache)),
		updater.NewPodIngressRule(d.cache, cloudData.PodIngressRules).RegisterListener(
			listener.NewPodIngressRule(d.cache)),
		updater.NewPodService(d.cache, cloudData.PodServices).RegisterListener(
			listener.NewPodService(d.cache, d.eventQueue)),
		updater.NewPodIngressRuleBackend(d.cache, cloudData.PodIngressRuleBackends).RegisterListener(
			listener.NewPodIngressRuleBackend(d.cache)),
		updater.NewPodServicePort(d.cache, cloudData.PodServicePorts).RegisterListener(
			listener.NewPodServicePort(d.cache)),
		updater.NewPodGroup(d.cache, cloudData.PodGroups).RegisterListener(
			listener.NewPodGroup(d.cache)),
		updater.NewPodGroupPort(d.cache, cloudData.PodGroupPorts).RegisterListener(
			listener.NewPodGroupPort(d.cache)),
		updater.NewPodReplicaSet(d.cache, cloudData.PodReplicaSets).RegisterListener(
			listener.NewPodReplicaSet(d.cache)),
		updater.NewPod(d.cache, cloudData.Pods).RegisterListener(
			listener.NewPod(d.cache, d.eventQueue)),
		updater.NewPrometheusTarget(d.cache, cloudData.PrometheusTargets).RegisterListener(
			listener.NewPrometheusTarget(d.cache)),
		updater.NewNetwork(d.cache, cloudData.Networks).RegisterListener(
			listener.NewNetwork(d.cache)),
		updater.NewSubnet(d.cache, cloudData.Subnets).RegisterListener(
			listener.NewSubnet(d.cache)),
		updater.NewVRouter(d.cache, cloudData.VRouters).RegisterListener(
			listener.NewVRouter(d.cache, d.eventQueue)),
		updater.NewRoutingTable(d.cache, cloudData.RoutingTables).RegisterListener(
			listener.NewRoutingTable(d.cache)),
		updater.NewDHCPPort(d.cache, cloudData.DHCPPorts).RegisterListener(
			listener.NewDHCPPort(d.cache, d.eventQueue)),
		updater.NewSecurityGroup(d.cache, cloudData.SecurityGroups).RegisterListener(
			listener.NewSecurityGroup(d.cache)),
		updater.NewSecurityGroupRule(d.cache, cloudData.SecurityGroupRules).RegisterListener(
			listener.NewSecurityGroupRule(d.cache)),
		updater.NewVMSecurityGroup(d.cache, cloudData.VMSecurityGroups).RegisterListener(
			listener.NewVMSecurityGroup(d.cache)),
		updater.NewNATGateway(d.cache, cloudData.NATGateways).RegisterListener(
			listener.NewNATGateway(d.cache, d.eventQueue)),
		updater.NewNATVMConnection(d.cache, cloudData.NATVMConnections).RegisterListener(
			listener.NewNATVMConnection(d.cache)),
		updater.NewNATRule(d.cache, cloudData.NATRules).RegisterListener(
			listener.NewNATRule(d.cache)),
		updater.NewLB(d.cache, cloudData.LBs).RegisterListener(
			listener.NewLB(d.cache, d.eventQueue)),
		updater.NewLBVMConnection(d.cache, cloudData.LBVMConnections).RegisterListener(
			listener.NewLBVMConnection(d.cache)),
		updater.NewLBListener(d.cache, cloudData.LBListeners).RegisterListener(
			listener.NewLBListener(d.cache)),
		updater.NewLBTargetServer(d.cache, cloudData.LBTargetServers).RegisterListener(
			listener.NewLBTargetServer(d.cache)),
		updater.NewRDSInstance(d.cache, cloudData.RDSInstances).RegisterListener(
			listener.NewRDSInstance(d.cache, d.eventQueue)),
		updater.NewRedisInstance(d.cache, cloudData.RedisInstances).RegisterListener(
			listener.NewRedisInstance(d.cache, d.eventQueue)),
		updater.NewPeerConnection(d.cache, cloudData.PeerConnections).RegisterListener(
			listener.NewPeerConnection(d.cache)),
		updater.NewCEN(d.cache, cloudData.CENs).RegisterListener(
			listener.NewCEN(d.cache)),
		updater.NewVInterface(d.cache, cloudData.VInterfaces, nil).RegisterListener(
			listener.NewVInterface(d.cache)),
		updater.NewFloatingIP(d.cache, cloudData.FloatingIPs).RegisterListener(
			listener.NewFloatingIP(d.cache)),
		ip,
		updater.NewVIP(d.cache, cloudData.VIPs).RegisterListener(
			listener.NewVIP(d.cache)),
		updater.NewVMPodNodeConnection(d.cache, cloudData.VMPodNodeConnections).RegisterListener( // VMPodNodeConnection需放在最后
			listener.NewVMPodNodeConnection(d.cache)),
		updater.NewProcess(d.cache, cloudData.Processes).RegisterListener(
			listener.NewProcess(d.cache, d.eventQueue)),
	}
}

// TODO common
func (r *domain) executeUpdaters(updatersInUpdateOrder []updater.ResourceUpdater) {
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

// TODO common
func (r *domain) notifyOnResourceChanged(updatersInUpdateOrder []updater.ResourceUpdater) {
	platformDataChanged := isPlatformDataChanged(updatersInUpdateOrder)
	if platformDataChanged {
		log.Infof("domain(%v) data changed, refresh platform data", r.domainLcuuid)
		refresh.RefreshCache([]common.DataChanged{common.DATA_CHANGED_PLATFORM_DATA})
	}
}

func (d *domain) updateSyncedAt(syncAt time.Time) {
	if syncAt.IsZero() {
		return
	}
	var domain mysql.Domain
	err := mysql.Db.Where("lcuuid = ?", d.domainLcuuid).First(&domain).Error
	if err != nil {
		log.Errorf("get domain (lcuuid: %s) from db failed: %s", d.domainLcuuid, err)
		return
	}
	domain.SyncedAt = &syncAt
	mysql.Db.Save(&domain)
	log.Debugf("update domain (%+v)", domain)
}

func (r *domain) updateStateInfo(cloudData cloudmodel.Resource) {
	var domain mysql.Domain
	err := mysql.Db.Where("lcuuid = ?", r.domainLcuuid).First(&domain).Error
	if err != nil {
		log.Errorf("get domain (lcuuid: %s) from db failed: %s", r.domainLcuuid, err)
		return
	}
	domain.State, domain.ErrorMsg = r.formatStateInfo(cloudData)
	mysql.Db.Save(&domain)
	log.Debugf("update domain (%+v)", domain)

	// TODO
	// for subDomainLcuuid, subDomainResource := range cloudData.SubDomainResources {
	// 	var subDomain mysql.SubDomain
	// 	err := mysql.Db.Where("lcuuid = ?", subDomainLcuuid).First(&subDomain).Error
	// 	if err != nil {
	// 		log.Errorf("get sub_domain (lcuuid: %s) from db failed: %s", subDomainLcuuid, err)
	// 		continue
	// 	}
	// 	subDomain.State = subDomainResource.ErrorState
	// 	subDomain.ErrorMsg = subDomainResource.ErrorMessage
	// 	mysql.Db.Save(&subDomain)
	// 	log.Debugf("update sub_domain (%+v)", subDomain)
	// }
}

func (d *domain) formatStateInfo(domainResource cloudmodel.Resource) (state int, errMsg string) {
	log.Infof("cloud domain (%s) state info: %d, %s", d.domainName, domainResource.ErrorState, domainResource.ErrorMessage)
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
