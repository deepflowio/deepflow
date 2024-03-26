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

package updater

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type PrometheusTarget struct {
	UpdaterBase[
		cloudmodel.PrometheusTarget,
		mysql.PrometheusTarget,
		*diffbase.PrometheusTarget,
		*message.PrometheusTargetAdd,
		message.PrometheusTargetAdd,
		*message.PrometheusTargetUpdate,
		message.PrometheusTargetUpdate,
		*message.PrometheusTargetFieldsUpdate,
		message.PrometheusTargetFieldsUpdate,
		*message.PrometheusTargetDelete,
		message.PrometheusTargetDelete]
}

func NewPrometheusTarget(wholeCache *cache.Cache, cloudData []cloudmodel.PrometheusTarget) *PrometheusTarget {
	updater := &PrometheusTarget{
		newUpdaterBase[
			cloudmodel.PrometheusTarget,
			mysql.PrometheusTarget,
			*diffbase.PrometheusTarget,
			*message.PrometheusTargetAdd,
			message.PrometheusTargetAdd,
			*message.PrometheusTargetUpdate,
			message.PrometheusTargetUpdate,
			*message.PrometheusTargetFieldsUpdate,
			message.PrometheusTargetFieldsUpdate,
			*message.PrometheusTargetDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN,
			wholeCache,
			db.NewPrometheusTarget().SetORG(wholeCache.GetORG()),
			wholeCache.DiffBaseDataSet.PrometheusTarget,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (p *PrometheusTarget) getDiffBaseByCloudItem(cloudItem *cloudmodel.PrometheusTarget) (diffBase *diffbase.PrometheusTarget, exits bool) {
	diffBase, exits = p.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *PrometheusTarget) generateDBItemToAdd(cloudItem *cloudmodel.PrometheusTarget) (*mysql.PrometheusTarget, bool) {
	podClusterID, exists := p.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Error(p.org.LogPre(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN, cloudItem.Lcuuid,
		)))
		return nil, false
	}
	vpcID, exists := p.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(p.org.LogPre(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN, cloudItem.Lcuuid,
		)))
		return nil, false
	}
	dbItem := &mysql.PrometheusTarget{
		Instance:     cloudItem.Instance,
		Job:          cloudItem.Job,
		ScrapeURL:    cloudItem.ScrapeURL,
		OtherLabels:  cloudItem.OtherLabels,
		VPCID:        vpcID,
		Domain:       p.cache.DomainLcuuid,
		SubDomain:    cloudItem.SubDomainLcuuid,
		PodClusterID: podClusterID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid

	return dbItem, true
}

func (p *PrometheusTarget) generateUpdateInfo(diffBase *diffbase.PrometheusTarget, cloudItem *cloudmodel.PrometheusTarget) (*message.PrometheusTargetFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.PrometheusTargetFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Instance != cloudItem.Instance {
		mapInfo["name"] = cloudItem.Instance
		structInfo.Name.Set(diffBase.Instance, cloudItem.Instance)
	}
	if diffBase.Job != cloudItem.Job {
		mapInfo["job"] = cloudItem.Job
		structInfo.Job.Set(diffBase.Job, cloudItem.Job)
	}

	if diffBase.ScrapeURL != cloudItem.ScrapeURL {
		mapInfo["scrape_url"] = cloudItem.ScrapeURL
		structInfo.ScrapeURL.Set(diffBase.ScrapeURL, cloudItem.ScrapeURL)
	}

	if diffBase.OtherLabels != cloudItem.OtherLabels {
		mapInfo["other_labels"] = cloudItem.OtherLabels
		structInfo.OtherLabels.Set(diffBase.OtherLabels, cloudItem.OtherLabels)
	}
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := p.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Error(p.org.LogPre(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_PROMETHEUS_TARGET_EN, cloudItem.Lcuuid,
			)))
			return nil, nil, false
		}
		mapInfo["epc_id"] = vpcID
		structInfo.VPCID.SetNew(vpcID)
		structInfo.VPCLcuuid.Set(diffBase.VPCLcuuid, cloudItem.VPCLcuuid)
	}
	return structInfo, mapInfo, len(mapInfo) > 0
}
