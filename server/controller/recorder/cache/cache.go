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

package cache

import (
	"context"
	"math/rand"
	"time"

	"github.com/op/go-logging"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	tagrecorderHealer "github.com/deepflowio/deepflow/server/controller/tagrecorder/healer"
)

// 为支持domain及其sub_domain的独立刷新，将缓存拆分成对应的独立Cache
type CacheManager struct {
	ctx context.Context

	metadata *rcommon.Metadata

	cacheSetSelfHealInterval time.Duration
	DomainCache              *Cache
	SubDomainCacheMap        map[string]*Cache
}

func NewCacheManager(ctx context.Context, cfg config.RecorderConfig, md *rcommon.Metadata) *CacheManager {
	mng := &CacheManager{
		ctx: ctx,

		metadata: md,

		cacheSetSelfHealInterval: time.Minute * time.Duration(cfg.CacheRefreshInterval),
		SubDomainCacheMap:        make(map[string]*Cache),
	}
	mng.DomainCache = NewCache(ctx, md, mng.cacheSetSelfHealInterval)

	var subDomains []*metadbmodel.SubDomain
	err := mng.metadata.DB.Where(map[string]interface{}{"domain": mng.metadata.GetDomainLcuuid()}).Find(&subDomains).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN, err), mng.metadata.LogPrefixes)
		return mng
	}
	log.Infof("new sub_domain cache count: %d", len(subDomains), mng.metadata.LogPrefixes)
	for _, subDomain := range subDomains {
		smd := mng.metadata.Copy()
		smd.SetSubDomain(*subDomain)
		mng.SubDomainCacheMap[subDomain.Lcuuid] = mng.CreateSubDomainCacheIfNotExists(smd)
	}
	return mng
}

func (m *CacheManager) CreateSubDomainCacheIfNotExists(md *rcommon.Metadata) *Cache {
	if _, exists := m.SubDomainCacheMap[md.GetSubDomainLcuuid()]; !exists {
		log.Infof("new subdomain cache (lcuuid: %s) because not exists", md.GetSubDomainLcuuid(), m.metadata.LogPrefixes)
		m.SubDomainCacheMap[md.GetSubDomainLcuuid()] = NewCache(m.ctx, md, m.cacheSetSelfHealInterval)
	}
	return m.SubDomainCacheMap[md.GetSubDomainLcuuid()]
}

type Cache struct {
	ctx context.Context

	metadata *rcommon.Metadata

	SelfHealInterval time.Duration
	RefreshSignal    chan struct{} // 用于限制并发刷新
	Sequence         int           // 缓存的序列标识，根据刷新递增；为debug方便，设置为公有属性，需避免直接修改值，使用接口修改

	diffBases      *diffbase.DiffBases
	tool          *tool.Tool
	refreshers refreshers
	refreshFailed   bool // 用于记录单次整体刷新结果,在每次刷新前重置

	tagrecorderHealers *tagrecorderHealer.Healers // tagrecorder 的 healer，用于处理 tag 相关的资源
}

func NewCache(ctx context.Context, md *rcommon.Metadata, selfHealInterval time.Duration) *Cache {
	tool := tool.NewTool(md)
	diffBases := diffbase.NewDiffBases(tool)
	c := &Cache{
		ctx: ctx,

		metadata: md,

		SelfHealInterval: selfHealInterval + time.Duration(rand.Intn(60))*time.Minute, // add random interval to avoid all cache refresh at once
		RefreshSignal:    make(chan struct{}, 1),
		diffBases:      diffBases, // 所有资源的主要信息，用于与cloud数据比较差异，根据差异更新资源
		tool:          tool,     // 各类资源的映射关系，用于按需进行数据转换
		refreshers:      newRefreshers(md, diffBases, tool),
	}
	c.tagrecorderHealers = tagrecorderHealer.NewHealers(md.Platform)
	c.StartSelfHealing()
	return c
}

func (c Cache) Tool() *tool.Tool {
	return c.tool
}

func (c Cache) DiffBases() *diffbase.DiffBases {
	return c.diffBases
}

func (c *Cache) GetMetadata() *rcommon.Metadata {
	return c.metadata
}

func (c *Cache) GetSequence() int {
	return c.Sequence
}

func (c *Cache) SetSequence(sequence int) {
	c.Sequence = sequence
}

func (c *Cache) IncrementSequence() {
	c.Sequence++
}

func (c *Cache) SetLogLevel(level logging.Level, caller string) {
	log.Infof("set cache log level to %s (caller: %s)", level.String(), caller, c.metadata.LogPrefixes)
	c.diffBases.SetLogLevel(level)
	c.tool.SetLogLevel(level)
}

const (
	RefreshSignalCallerSelfHeal  = "self_heal"
	RefreshSignalCallerDomain    = "domain"
	RefreshSignalCallerSubDomain = "sub_domain"
)

func (c *Cache) ResetRefreshSignal(caller string) {
	log.Infof("domain: %s reset cache refresh signal (caller: %s)", c.metadata.GetDomainLcuuid(), caller, c.metadata.LogPrefixes)
	c.RefreshSignal <- struct{}{}
}

func (c *Cache) StartSelfHealing() {
	go func() {
		log.Infof("recorder cache self-healing started, interval: %s", c.SelfHealInterval.String(), c.metadata.LogPrefixes)
		c.ResetRefreshSignal(RefreshSignalCallerSelfHeal)
		c.TryRefresh()

		ticker := time.NewTicker(c.SelfHealInterval)
		defer ticker.Stop()

	LOOP:
		for {
			select {
			case <-ticker.C:
				c.TryRefresh()
			case <-c.ctx.Done():
				break LOOP
			}
		}
		log.Info("recorder cache self-healing completed", c.metadata.LogPrefixes)
	}()
}

func (c *Cache) TryRefresh() bool {
	select {
	case <-c.RefreshSignal:
		c.Refresh()
		return true
	default:
		log.Warning("last cache refresh not completed now", c.metadata.LogPrefixes)
		return false
	}

}

func (c *Cache) triggerTagrecorderHealers() {
	if c.needTagSelfHealing() {
		c.tagrecorderHealers.Run()
	} else {
		log.Info("tagrecorder self-healing is disabled", c.metadata.LogPrefixes)
	}
}

func (c *Cache) needSelfHealing() bool {
	return c.metadata.Config.SelfHealCfg.Enabled || c.Sequence == 0
}

func (c *Cache) needTagSelfHealing() bool {
	return c.metadata.Config.TagRecorderSelfHealCfg.Enabled || c.Sequence == 0
}

func (c *Cache) randomSleep() {
	if c.Sequence == 0 {
		return
	}
	// 生成 10-30 的随机数（对应 1.0-3.0 秒，粒度 0.1秒）
	randomValue := rand.Intn(21) + 10 // 0-20 + 10 = 10-30
	// 转换为 Duration（乘以 0.1秒 = 100毫秒）
	duration := time.Duration(randomValue) * 100 * time.Millisecond
	time.Sleep(duration)
	log.Infof("cache refresh sleep %s", duration.String(), c.metadata.LogPrefixes)
}

// 所有缓存的刷新入口
func (c *Cache) Refresh() {
	defer c.ResetRefreshSignal(RefreshSignalCallerSelfHeal)
	c.triggerTagrecorderHealers()

	if !c.needSelfHealing() {
		log.Info("self-healing is disabled", c.metadata.LogPrefixes)
		return
	}

	log.Infof("cache self-healing started, sequence now: %d", c.Sequence, c.metadata.LogPrefixes)
	oldTool := c.tool
	oldDiffBases := c.diffBases

	c.tool = tool.NewTool(c.metadata)
	c.diffBases = diffbase.NewDiffBases(c.tool)
	c.refreshers = newRefreshers(c.metadata, c.diffBases, c.tool)
	c.SetLogLevel(logging.DEBUG, RefreshSignalCallerSelfHeal)
	c.refreshFailed = false

	// 分类刷新资源的相关缓存

	// TODO refactor
	// sub domain需要使用vpc、vm的映射数据

	refresh := func(resourceType string) {
		if !c.refreshers.refresh(resourceType, c.Sequence) {
			c.refreshFailed = true
		}
	}

	refresh(ctrlrcommon.RESOURCE_TYPE_REGION_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_AZ_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_VPC_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_HOST_EN)
	c.randomSleep()
	refresh(ctrlrcommon.RESOURCE_TYPE_VM_EN)
	c.randomSleep()

	// 仅domain缓存需要刷新的资源
	if c.metadata.GetSubDomainLcuuid() == "" {
		refresh(ctrlrcommon.RESOURCE_TYPE_SUB_DOMAIN_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_NAT_VM_CONNECTION_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_LB_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_LB_VM_CONNECTION_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_CEN_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN)
		refresh(ctrlrcommon.RESOURCE_TYPE_VIP_EN)
	}

	refresh(ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_PORT_EN)
	c.randomSleep()
	refresh(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN)
	c.randomSleep()
	refresh(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_PORT_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN)
	c.randomSleep()
	refresh(ctrlrcommon.RESOURCE_TYPE_POD_EN)
	c.randomSleep()
	refresh(ctrlrcommon.RESOURCE_TYPE_CONFIG_MAP_EN)
	c.randomSleep()
	refresh(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_CONFIG_MAP_CONNECTION_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_NETWORK_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN)
	refresh(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN)
	c.randomSleep()
	refresh(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN)
	c.randomSleep()
	refresh(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN)
	c.randomSleep()
	refresh(ctrlrcommon.RESOURCE_TYPE_PROCESS_EN)

	// FIXME
	if c.refreshFailed {
		log.Errorf("cache self-healing failed, sequence now: %d", c.Sequence, c.metadata.LogPrefixes)
		c.diffBases = oldDiffBases
		c.tool = oldTool
		c.refreshers = newRefreshers(c.metadata, c.diffBases, c.tool)
	} else {
		log.Infof("cache self-healing completed, sequence now: %d", c.Sequence, c.metadata.LogPrefixes)
	}
}
