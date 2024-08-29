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

package encoder

import (
	"fmt"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"google.golang.org/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
	prometheuscommon "github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

// 缓存资源可用于分配的ID，提供ID的刷新、分配、回收接口
type target struct {
	org          *prometheuscommon.ORG
	lock         sync.Mutex
	resourceType string
	keyToID      sync.Map
	descIDAllocator
}

func newTarget(org *prometheuscommon.ORG, max int) *target {
	ln := &target{
		org:          org,
		resourceType: "target",
	}
	// both recorder and prometheus need to insert data into prometheus_target, they equally share the id pool of prometheus_target.
	// recorder uses ids [1, max/2+max%2], prometheus uses ids [max/2+max%2+1, max].
	ln.descIDAllocator = newDescIDAllocator(org, ln.resourceType, max/2+max%2+1, max)
	ln.rawDataProvider = ln
	return ln
}

func (ln *target) getID(key cache.TargetKey) (int, bool) {
	if item, ok := ln.keyToID.Load(key); ok {
		return item.(int), true
	}
	return 0, false
}

func (ln *target) refresh(args ...interface{}) error {
	ln.lock.Lock()
	defer ln.lock.Unlock()

	return ln.descIDAllocator.refresh()
}

func (ln *target) encode(ts []*controller.PrometheusTargetRequest) ([]*controller.PrometheusTarget, error) {
	ln.lock.Lock()
	defer ln.lock.Unlock()

	resp := make([]*controller.PrometheusTarget, 0)
	var dbToAdd []*mysqlmodel.PrometheusTarget
	podClusterIDToDomainInfo, err := ln.getPodClusterIDToDomainInfo()
	for i := range ts {
		t := ts[i]
		ins := t.GetInstance()
		job := t.GetJob()
		vpcID := int(t.GetEpcId())
		podClusterID := int(t.GetPodClusterId())
		if id, ok := ln.keyToID.Load(cache.NewTargetKey(ins, job, vpcID, podClusterID)); ok {
			resp = append(resp, &controller.PrometheusTarget{
				Id:           proto.Uint32(uint32(id.(int))),
				Instance:     &ins,
				Job:          &job,
				PodClusterId: proto.Uint32(uint32(podClusterID)),
				EpcId:        proto.Uint32(uint32(vpcID)),
			})
			continue
		}
		di := podClusterIDToDomainInfo[podClusterID]
		dbToAdd = append(dbToAdd, &mysqlmodel.PrometheusTarget{
			Base:         mysqlmodel.Base{Lcuuid: common.GenerateUUID(ins + job + fmt.Sprintf("%d-%d", vpcID, podClusterID) + "prometheus")},
			CreateMethod: common.PROMETHEUS_TARGET_CREATE_METHOD_PROMETHEUS,
			Instance:     ins,
			Job:          job,
			VPCID:        vpcID,
			PodClusterID: podClusterID,
			Domain:       di.domain,
			SubDomain:    di.subDomain,
		})
	}
	if len(dbToAdd) == 0 {
		return resp, nil
	}
	ids, err := ln.allocate(len(dbToAdd))
	if err != nil {
		return nil, err
	}
	for i := range ids {
		dbToAdd[i].ID = ids[i]
	}
	err = addBatch(ln.org.DB, dbToAdd, ln.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", ln.resourceType, err.Error(), ln.org.LogPrefix)
		return nil, err
	}
	for i := range dbToAdd {
		id := dbToAdd[i].ID
		k := cache.NewTargetKey(dbToAdd[i].Instance, dbToAdd[i].Job, dbToAdd[i].VPCID, dbToAdd[i].PodClusterID)
		ln.keyToID.Store(k, id)
		resp = append(resp, &controller.PrometheusTarget{
			Id:           proto.Uint32(uint32(id)),
			Instance:     &k.Instance,
			Job:          &k.Job,
			PodClusterId: proto.Uint32(uint32(k.PodClusterID)),
			EpcId:        proto.Uint32(uint32(k.VPCID)),
		})
	}
	return resp, nil
}

func (ln *target) load() (ids mapset.Set[int], err error) {
	var items []*mysqlmodel.PrometheusTarget
	err = ln.org.DB.Unscoped().Where(&mysqlmodel.PrometheusTarget{CreateMethod: common.PROMETHEUS_TARGET_CREATE_METHOD_PROMETHEUS}).Find(&items).Error
	if err != nil {
		log.Errorf("db query %s failed: %v", ln.resourceType, err, ln.org.LogPrefix)
		return nil, err
	}

	inUseIDSet := mapset.NewSet[int]()
	for _, item := range items {
		inUseIDSet.Add(item.ID)
		ln.keyToID.Store(cache.NewTargetKey(item.Instance, item.Job, item.VPCID, item.PodClusterID), item.ID)
	}
	return inUseIDSet, nil
}

func (ln *target) check(ids []int) (inUseIDs []int, err error) {
	var dbItems []*mysqlmodel.PrometheusTarget
	err = ln.org.DB.Unscoped().Where("id IN ?", ids).Find(&dbItems).Error
	if err != nil {
		log.Errorf("db query %s failed: %v", ln.resourceType, err, ln.org.LogPrefix)
		return
	}
	if len(dbItems) != 0 {
		for _, item := range dbItems {
			inUseIDs = append(inUseIDs, item.ID)
		}
		log.Infof("%s ids: %+v are in use.", ln.resourceType, inUseIDs, ln.org.LogPrefix)
	}
	return
}

type domainInfo struct {
	domain    string
	subDomain string
}

func (ln *target) getPodClusterIDToDomainInfo() (podClusterIDToDomainInfo map[int]domainInfo, err error) {
	var podClusters []*mysqlmodel.PodCluster
	err = ln.org.DB.Unscoped().Find(&podClusters).Error
	if err != nil {
		log.Errorf("db query pod cluster failed: %v", err, ln.org.LogPrefix)
		return
	}
	podClusterIDToDomainInfo = make(map[int]domainInfo)
	for _, podCluster := range podClusters {
		podClusterIDToDomainInfo[podCluster.ID] = domainInfo{domain: podCluster.Domain, subDomain: podCluster.SubDomain}
	}
	return
}
