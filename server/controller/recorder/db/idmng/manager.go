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

package idmng

import (
	"sort"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/op/go-logging"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/query"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	. "github.com/deepflowio/deepflow/server/controller/recorder/config"
	. "github.com/deepflowio/deepflow/server/controller/recorder/constraint"
)

var log = logging.MustGetLogger("recorder.idmng")

type IDManager struct {
	org *common.ORG

	resourceTypeToIDPool map[string]IDPoolUpdater
}

func newIDManager(cfg RecorderConfig, orgID int) (*IDManager, error) {
	org, err := common.NewORG(orgID)
	if err != nil {
		log.Errorf("failed to create org object: %s", err.Error())
		return nil, err
	}
	mng := &IDManager{org: org}
	mng.resourceTypeToIDPool = map[string]IDPoolUpdater{
		ctrlrcommon.RESOURCE_TYPE_REGION_EN:        newIDPool[mysql.Region](mng.org, ctrlrcommon.RESOURCE_TYPE_REGION_EN, cfg.ResourceMaxID0),
		ctrlrcommon.RESOURCE_TYPE_AZ_EN:            newIDPool[mysql.AZ](mng.org, ctrlrcommon.RESOURCE_TYPE_AZ_EN, cfg.ResourceMaxID0),
		ctrlrcommon.RESOURCE_TYPE_HOST_EN:          newIDPool[mysql.Host](mng.org, ctrlrcommon.RESOURCE_TYPE_HOST_EN, cfg.ResourceMaxID0),
		ctrlrcommon.RESOURCE_TYPE_VPC_EN:           newIDPool[mysql.VPC](mng.org, ctrlrcommon.RESOURCE_TYPE_VPC_EN, cfg.ResourceMaxID0),
		ctrlrcommon.RESOURCE_TYPE_NETWORK_EN:       newIDPool[mysql.Network](mng.org, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cfg.ResourceMaxID0),
		ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN:   newIDPool[mysql.PodCluster](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cfg.ResourceMaxID0),
		ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN: newIDPool[mysql.PodNamespace](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cfg.ResourceMaxID0),

		ctrlrcommon.RESOURCE_TYPE_VM_EN:              newIDPool[mysql.VM](mng.org, ctrlrcommon.RESOURCE_TYPE_VM_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_VROUTER_EN:         newIDPool[mysql.VRouter](mng.org, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN:       newIDPool[mysql.DHCPPort](mng.org, ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN:    newIDPool[mysql.RDSInstance](mng.org, ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN:  newIDPool[mysql.RedisInstance](mng.org, ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN:     newIDPool[mysql.NATGateway](mng.org, ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_LB_EN:              newIDPool[mysql.LB](mng.org, ctrlrcommon.RESOURCE_TYPE_LB_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN:        newIDPool[mysql.PodNode](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN:     newIDPool[mysql.PodService](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_POD_EN:             newIDPool[mysql.Pod](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN:     newIDPool[mysql.PodIngress](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN:       newIDPool[mysql.PodGroup](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN: newIDPool[mysql.PodReplicaSet](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_PROCESS_EN:         newIDPool[mysql.Process](mng.org, ctrlrcommon.RESOURCE_TYPE_PROCESS_EN, cfg.ResourceMaxID1),

		// both recorder and prometheus need to insert data into prometheus_target, they equally share the id pool of prometheus_target.
		// recorder uses ids [1, max/2+max%2], prometheus uses ids [max/2+max%2+1, max].
		ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN: newIDPool[mysql.PrometheusTarget](mng.org, ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN, cfg.ResourceMaxID1/2+cfg.ResourceMaxID1%2),
	}
	return mng, nil
}

func (m *IDManager) Refresh() error {
	log.Info(m.org.LogPre("refresh id pools"))
	var result error
	for _, idPool := range m.resourceTypeToIDPool {
		err := idPool.refresh()
		if err != nil {
			result = err
		}
	}
	return result
}

func (m *IDManager) AllocateIDs(resourceType string, count int) []int {
	idPool, ok := m.resourceTypeToIDPool[resourceType]
	if !ok {
		log.Error(m.org.LogPre("resource type (%s) does not need to allocate id", resourceType))
		return []int{}
	}
	ids, _ := idPool.allocate(count)
	return ids
}

func (m *IDManager) RecycleIDs(resourceType string, ids []int) {
	idPool, ok := m.resourceTypeToIDPool[resourceType]
	if !ok {
		log.Error(m.org.LogPre("resource type (%s) does not need to allocate id", resourceType))
		return
	}
	idPool.recycle(ids)
	return
}

type IDPoolUpdater interface {
	refresh() error
	allocate(count int) ([]int, error)
	recycle(ids []int)
}

// 缓存资源可用于分配的ID，提供ID的刷新、分配、回收接口
type IDPool[MT MySQLModel] struct {
	org          *common.ORG
	resourceType string
	mutex        sync.RWMutex
	max          int
	usableIDs    []int
}

func newIDPool[MT MySQLModel](org *common.ORG, resourceType string, max int) *IDPool[MT] {
	return &IDPool[MT]{
		org: org,

		resourceType: resourceType,
		max:          max,
	}
}

func (p *IDPool[MT]) refresh() error {
	log.Info(p.org.LogPre("refresh %s id pools started", p.resourceType))

	var items []*MT
	var err error
	// TODO do not handle concrete resource in common, create new type IDPool for process and target
	if p.resourceType == ctrlrcommon.RESOURCE_TYPE_PROCESS_EN {
		items, err = query.FindInBatches[MT](p.org.DB.Unscoped().Select("id"))
	} else if p.resourceType == ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN {
		err = p.org.DB.Unscoped().Where(&mysql.PrometheusTarget{CreateMethod: ctrlrcommon.PROMETHEUS_TARGET_CREATE_METHOD_RECORDER}).Select("id").Find(&items).Error
	} else {
		err = p.org.DB.Unscoped().Select("id").Find(&items).Error
	}
	if err != nil {
		log.Error(p.org.LogPre("db query %s failed: %v", p.resourceType, err))
		return err
	}
	inUseIDsSet := mapset.NewSet[int]()
	for _, item := range items {
		inUseIDsSet.Add((*item).GetID())
	}
	allIDsSet := mapset.NewSet[int]()
	for i := 1; i <= p.max; i++ {
		allIDsSet.Add(i)
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()
	// 可用ID = 所有ID（1~max）- db中正在使用的ID
	// 排序原则：大于db正在使用的max值的ID（未曾被使用过的ID）优先，小于db正在使用的max值的ID（已被使用过且已回收的ID）在后
	var usableIDs []int
	if inUseIDsSet.Cardinality() != 0 {
		inUseIDs := inUseIDsSet.ToSlice()
		sort.IntSlice(inUseIDs).Sort()
		maxInUseID := inUseIDs[len(inUseIDs)-1]

		usableIDsSet := allIDsSet.Difference(inUseIDsSet)
		usedIDs := []int{}
		usableIDs = usableIDsSet.ToSlice()
		sort.IntSlice(usableIDs).Sort()
		for _, id := range usableIDs {
			if id < maxInUseID {
				usedIDs = append(usedIDs, id)
				usableIDsSet.Remove(id)
			} else {
				break
			}
		}
		usableIDs = usableIDsSet.ToSlice()
		sort.IntSlice(usableIDs).Sort()
		sort.IntSlice(usedIDs).Sort()
		usableIDs = append(usableIDs, usedIDs...)
	} else {
		usableIDs = allIDsSet.ToSlice()
		sort.IntSlice(usableIDs).Sort()
	}
	p.usableIDs = usableIDs

	log.Info(p.org.LogPre("refresh %s id pools (usable ids count: %d) completed", p.resourceType, len(p.usableIDs)))
	return nil
}

// 批量分配ID，若ID池中数量不足，分配ID池所有ID；反之分配指定个数ID。
// 分配的ID中，若已有被实际使用的ID（闭源页面创建使用），排除已使用ID，仅分配剩余部分。
func (p *IDPool[MT]) allocate(count int) (ids []int, err error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if len(p.usableIDs) == 0 {
		log.Error(p.org.LogPre("%s has no more usable ids", p.resourceType))
		return
	}

	trueCount := count
	if len(p.usableIDs) < count {
		trueCount = len(p.usableIDs)
	}
	ids = make([]int, trueCount)
	copy(ids, p.usableIDs[:trueCount])
	p.usableIDs = p.usableIDs[trueCount:]

	var dbItems []*MT
	err = p.org.DB.Unscoped().Where("id IN ?", ids).Find(&dbItems).Error
	if err != nil {
		log.Error(p.org.LogPre("db query %s failed: %v", p.resourceType, err))
		return
	}
	if len(dbItems) != 0 {
		inUseIDs := make([]int, 0, len(dbItems))
		for _, item := range dbItems {
			inUseIDs = append(inUseIDs, (*item).GetID())
		}
		log.Info(p.org.LogPre("%s ids: %+v are in use.", p.resourceType, inUseIDs))
		ids = mapset.NewSet(ids...).Difference(mapset.NewSet(inUseIDs...)).ToSlice()
	}
	log.Info(p.org.LogPre("allocate %s ids: %v (expected count: %d, true count: %d)", p.resourceType, ids, count, len(ids)))
	return
}

func (p *IDPool[MT]) recycle(ids []int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	sort.IntSlice(ids).Sort()
	p.usableIDs = append(p.usableIDs, ids...)
	log.Info(p.org.LogPre("recycle %s ids: %v", p.resourceType, ids))
}
