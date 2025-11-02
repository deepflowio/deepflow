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
	"fmt"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	mysql "github.com/deepflowio/deepflow/server/controller/db/metadb"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/query"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	. "github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("recorder.idmng")

var minID = 1

type IDManager struct {
	org *common.ORG

	resourceTypeToIDPool map[string]IDPoolUpdater
}

func newIDManager(cfg RecorderConfig, orgID int) (*IDManager, error) {
	log.Infof("create id manager for org: %d", orgID)
	org, err := common.NewORG(orgID)
	if err != nil {
		log.Errorf("failed to create org object: %s", err.Error())
		return nil, err
	}
	mng := &IDManager{org: org}
	mng.resourceTypeToIDPool = map[string]IDPoolUpdater{
		ctrlrcommon.RESOURCE_TYPE_REGION_EN:        newIDPool[mysqlmodel.Region](mng.org, ctrlrcommon.RESOURCE_TYPE_REGION_EN, cfg.ResourceMaxID0),
		ctrlrcommon.RESOURCE_TYPE_AZ_EN:            newIDPool[mysqlmodel.AZ](mng.org, ctrlrcommon.RESOURCE_TYPE_AZ_EN, cfg.ResourceMaxID0),
		ctrlrcommon.RESOURCE_TYPE_HOST_EN:          newIDPool[mysqlmodel.Host](mng.org, ctrlrcommon.RESOURCE_TYPE_HOST_EN, cfg.ResourceMaxID0),
		ctrlrcommon.RESOURCE_TYPE_VPC_EN:           newIDPool[mysqlmodel.VPC](mng.org, ctrlrcommon.RESOURCE_TYPE_VPC_EN, cfg.ResourceMaxID0),
		ctrlrcommon.RESOURCE_TYPE_NETWORK_EN:       newIDPool[mysqlmodel.Network](mng.org, ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cfg.ResourceMaxID0),
		ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN:   newIDPool[mysqlmodel.PodCluster](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cfg.ResourceMaxID0),
		ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN: newIDPool[mysqlmodel.PodNamespace](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cfg.ResourceMaxID0),

		ctrlrcommon.RESOURCE_TYPE_VM_EN:              newIDPool[mysqlmodel.VM](mng.org, ctrlrcommon.RESOURCE_TYPE_VM_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_VROUTER_EN:         newIDPool[mysqlmodel.VRouter](mng.org, ctrlrcommon.RESOURCE_TYPE_VROUTER_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN:       newIDPool[mysqlmodel.DHCPPort](mng.org, ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN:    newIDPool[mysqlmodel.RDSInstance](mng.org, ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN:  newIDPool[mysqlmodel.RedisInstance](mng.org, ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN:     newIDPool[mysqlmodel.NATGateway](mng.org, ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_LB_EN:              newIDPool[mysqlmodel.LB](mng.org, ctrlrcommon.RESOURCE_TYPE_LB_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN:        newIDPool[mysqlmodel.PodNode](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN:     newIDPool[mysqlmodel.PodService](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_POD_EN:             newIDPool[mysqlmodel.Pod](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN:     newIDPool[mysqlmodel.PodIngress](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN:       newIDPool[mysqlmodel.PodGroup](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN: newIDPool[mysqlmodel.PodReplicaSet](mng.org, ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_PROCESS_EN:         newIDPool[mysqlmodel.Process](mng.org, ctrlrcommon.RESOURCE_TYPE_PROCESS_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_GPROCESS_EN:        newProcessGIDPool(mng.org, ctrlrcommon.RESOURCE_TYPE_GPROCESS_EN, cfg.ResourceMaxID1),
		ctrlrcommon.RESOURCE_TYPE_VTAP_EN:            newIDPool[mysqlmodel.VTap](mng.org, ctrlrcommon.RESOURCE_TYPE_VTAP_EN, cfg.ResourceMaxID0),
	}

	orgTableExists, err := mysql.CheckIfORGTableExists()
	if err != nil {
		log.Errorf("failed to check if org table exists: %s", err.Error())
		return nil, err
	}
	if orgTableExists && orgID == ctrlrcommon.DEFAULT_ORG_ID {
		mng.resourceTypeToIDPool[ctrlrcommon.RESOURCE_TYPE_ORG_EN] = newORGIDPool(
			mng.org, ctrlrcommon.RESOURCE_TYPE_ORG_EN, ctrlrcommon.ORG_ID_MAX,
		)
	}
	return mng, nil
}

func (m *IDManager) Refresh() error {
	log.Info("refresh id pools started", m.org.LogPrefix)
	defer log.Info("refresh id pools completed", m.org.LogPrefix)

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
		log.Errorf("resource type: %s does not need to allocate id", resourceType, m.org.LogPrefix)
		return []int{}
	}
	ids, _ := idPool.allocate(count)
	return ids
}

func (m *IDManager) RecycleIDs(resourceType string, ids []int) {
	idPool, ok := m.resourceTypeToIDPool[resourceType]
	if !ok {
		log.Errorf("resource type: %s does not need to allocate id", resourceType, m.org.LogPrefix)
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

type idGetter[MT mysqlmodel.ResourceNeedBeAllocatedIDConstraint] interface {
	getRealID(*MT) int
}

// 缓存资源可用于分配的ID，提供ID的刷新、分配、回收接口
type IDPool[MT mysqlmodel.ResourceNeedBeAllocatedIDConstraint] struct {
	mutex    sync.RWMutex
	keyField string
	AscIDAllocator

	idGetter idGetter[MT]
}

func newIDPool[MT mysqlmodel.ResourceNeedBeAllocatedIDConstraint](org *common.ORG, resourceType string, max int) *IDPool[MT] {
	p := &IDPool[MT]{
		keyField:       "id",
		AscIDAllocator: NewAscIDAllocator(org, resourceType, minID, max),
	}
	p.SetInUseIDsProvider(p)
	return p
}

func (p *IDPool[MT]) resetKeyField(keyField string) {
	p.keyField = keyField
}

func (p *IDPool[MT]) load() (mapset.Set[int], error) {
	items, err := query.FindInBatches[MT](p.org.DB.Unscoped().Select(p.keyField))
	if err != nil {
		log.Errorf("failed to query %s: %v", p.resourceType, err, p.org.LogPrefix)
		return nil, err
	}
	inUseIDsSet := mapset.NewSet[int]()
	for _, item := range items {
		inUseIDsSet.Add(p.getID(item))
	}
	log.Infof("loaded %s ids successfully", p.resourceType, p.org.LogPrefix)
	return inUseIDsSet, nil
}

func (p *IDPool[MT]) check(ids []int) ([]int, error) {
	var dbItems []*MT
	err := p.org.DB.Unscoped().Where(fmt.Sprintf("%s IN ?", p.keyField), ids).Find(&dbItems).Error
	if err != nil {
		log.Errorf("failed to query %s: %v", p.resourceType, err, p.org.LogPrefix)
		return nil, err
	}
	inUseIDs := make([]int, 0)
	if len(dbItems) != 0 {
		for _, item := range dbItems {
			inUseIDs = append(inUseIDs, p.getID(item))
		}
		log.Infof("%s ids: %+v are in use.", p.resourceType, inUseIDs, p.org.LogPrefix)
	}
	return inUseIDs, nil
}

func (p *IDPool[MT]) getID(item *MT) int {
	if p.idGetter == nil {
		return (*item).GetID()
	}
	return p.idGetter.getRealID(item)
}

func (p *IDPool[MT]) refresh() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.Refresh()
}

// 批量分配ID，若ID池中数量不足，分配ID池所有ID；反之分配指定个数ID。
// 分配的ID中，若已有被实际使用的ID（闭源页面创建使用），排除已使用ID，仅分配剩余部分。
func (p *IDPool[MT]) allocate(count int) (ids []int, err error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.Allocate(count)
}

func (p *IDPool[MT]) recycle(ids []int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.Recycle(ids)
}

type ProcessGIDPool struct {
	*IDPool[mysqlmodel.Process]
}

func newProcessGIDPool(org *common.ORG, resourceType string, max int) IDPoolUpdater {
	p := &ProcessGIDPool{newIDPool[mysqlmodel.Process](org, resourceType, max)}
	p.idGetter = p
	p.resetKeyField("gid")
	return p
}

func (p *ProcessGIDPool) getRealID(item *mysqlmodel.Process) int {
	return int(item.GID)
}

type ORGIDPool struct {
	*IDPool[mysqlmodel.ORG]
}

func newORGIDPool(org *common.ORG, resourceType string, max int) IDPoolUpdater {
	p := &ORGIDPool{newIDPool[mysqlmodel.ORG](org, resourceType, max)}
	p.idGetter = p
	p.resetKeyField("org_id")
	return p
}

func (p *ORGIDPool) getRealID(item *mysqlmodel.ORG) int {
	return item.ORGID
}
