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

package script

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

func (s scripts) Version7_1_0_28(db *gorm.DB) error {
	log.Infof("executing script")
	// 1. 获取所有的 model.CustomService
	var customServices []model.CustomService
	if err := db.Find(&customServices).Error; err != nil {
		log.Errorf("failed to query custom_service: %v", err)
		return err
	}

	if len(customServices) == 0 {
		log.Info("no custom_service to migrate")
		return nil
	}

	// 2. 遍历所有的 model.CustomService, 构建 custom_service_id -> epc_id/pod_cluster_id 的映射
	// 收集所有需要查询的 epc_id 和 pod_cluster_id
	epcIDs := make(map[int]bool)
	podClusterIDs := make(map[int]bool)
	customServiceToResourceID := make(map[int]struct {
		isEPC bool
		id    int
	})

	for _, cs := range customServices {
		var resourceID int
		var isEPC bool

		if len(cs.VPCIDs) > 0 {
			// epc_ids 有值，使用第一个 epc_id
			resourceID = cs.VPCIDs[0]
			isEPC = true
			epcIDs[resourceID] = true
		} else if len(cs.PodClusterIDs) > 0 {
			// epc_ids 为空，使用第一个 pod_cluster_id
			resourceID = cs.PodClusterIDs[0]
			isEPC = false
			podClusterIDs[resourceID] = true
		} else {
			// 两者都为空，跳过
			log.Debugf("custom_service id=%d name=%s has no epc_ids or pod_cluster_ids, skip", cs.ID, cs.Name)
			continue
		}

		customServiceToResourceID[cs.ID] = struct {
			isEPC bool
			id    int
		}{isEPC: isEPC, id: resourceID}
	}

	// 3. 通过 epc_id 和 pod_cluster_id 去查询 model.VPC, model.PodCluster 表
	// 获取 epc_id/pod_cluster_id -> domain 的映射
	resourceIDToDomain := make(map[string]string) // key: "epc_<id>" or "pod_cluster_<id>", value: domain

	// 查询 VPC
	if len(epcIDs) > 0 {
		var vpcs []model.VPC
		epcIDList := make([]int, 0, len(epcIDs))
		for id := range epcIDs {
			epcIDList = append(epcIDList, id)
		}
		if err := db.Select("id, domain").Where("id IN ?", epcIDList).Find(&vpcs).Error; err != nil {
			log.Errorf("failed to query vpc: %v", err)
			return err
		}
		for _, vpc := range vpcs {
			resourceIDToDomain[fmt.Sprintf("epc_%d", vpc.ID)] = vpc.Domain
		}
	}

	// 查询 PodCluster
	if len(podClusterIDs) > 0 {
		var podClusters []model.PodCluster
		podClusterIDList := make([]int, 0, len(podClusterIDs))
		for id := range podClusterIDs {
			podClusterIDList = append(podClusterIDList, id)
		}
		if err := db.Select("id, domain").Where("id IN ?", podClusterIDList).Find(&podClusters).Error; err != nil {
			log.Errorf("failed to query pod_cluster: %v", err)
			return err
		}
		for _, pc := range podClusters {
			resourceIDToDomain[fmt.Sprintf("pod_cluster_%d", pc.ID)] = pc.Domain
		}
	}

	// 4. 使用 domain 去查询 model.Domain 表, 获取其 lcuuid 与 team_id map, lcuuid 与 id map
	// 收集所有唯一的 domain
	domainSet := make(map[string]bool)
	for _, domain := range resourceIDToDomain {
		if domain != "" {
			domainSet[domain] = true
		}
	}

	domainList := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domainList = append(domainList, domain)
	}

	// 查询 Domain 表
	domainLcuuidToTeamID := make(map[string]int)
	domainLcuuidToDomainID := make(map[string]int)

	if len(domainList) > 0 {
		var domains []model.Domain
		if err := db.Select("id, lcuuid, team_id").Where("lcuuid IN ?", domainList).Find(&domains).Error; err != nil {
			log.Errorf("failed to query domain: %v", err)
			return err
		}
		for _, d := range domains {
			domainLcuuidToTeamID[d.Lcuuid] = d.TeamID
			domainLcuuidToDomainID[d.Lcuuid] = d.ID
		}
	}

	// 5. 遍历所有的 model.CustomService, 通过上面 3 个 map, 更新 model.CustomService 的 team_id 以及 domain, domain_id 字段
	for _, cs := range customServices {
		resourceInfo, exists := customServiceToResourceID[cs.ID]
		if !exists {
			continue
		}

		// 获取 domain
		var key string
		if resourceInfo.isEPC {
			key = fmt.Sprintf("epc_%d", resourceInfo.id)
		} else {
			key = fmt.Sprintf("pod_cluster_%d", resourceInfo.id)
		}

		domainLcuuid, ok := resourceIDToDomain[key]
		if !ok || domainLcuuid == "" {
			log.Warningf("custom_service id=%d name=%s cannot find domain for resource %s, skip", cs.ID, cs.Name, key)
			continue
		}

		// 获取 team_id 和 domain_id
		teamID, hasTeamID := domainLcuuidToTeamID[domainLcuuid]
		domainID, hasDomainID := domainLcuuidToDomainID[domainLcuuid]

		if !hasTeamID || !hasDomainID {
			log.Warningf("custom_service id=%d name=%s cannot find team_id or domain_id for domain %s, skip", cs.ID, cs.Name, domainLcuuid)
			continue
		}

		// 更新字段
		if err := db.Model(&model.CustomService{}).Where("id = ?", cs.ID).Updates(map[string]interface{}{
			"team_id":   teamID,
			"domain":    domainLcuuid,
			"domain_id": domainID,
		}).Error; err != nil {
			log.Errorf("failed to update custom_service id=%d: %v", cs.ID, err)
			return err
		}

		log.Infof("updated custom_service id=%d name=%s with team_id=%d domain=%s domain_id=%d",
			cs.ID, cs.Name, teamID, domainLcuuid, domainID)
	}

	log.Infof("successfully migrated %d custom_service records", len(customServiceToResourceID))
	return nil
}
