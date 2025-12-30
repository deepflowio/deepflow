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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type LBListener struct {
	UpdaterBase[
		cloudmodel.LBListener,
		*diffbase.LBListener,
		*metadbmodel.LBListener,
		metadbmodel.LBListener,
		*message.AddedLBListeners,
		message.AddedLBListeners,
		message.AddNoneAddition,
		*message.UpdatedLBListener,
		message.UpdatedLBListener,
		*message.UpdatedLBListenerFields,
		message.UpdatedLBListenerFields,
		*message.DeletedLBListeners,
		message.DeletedLBListeners,
		message.DeleteNoneAddition]
}

func NewLBListener(wholeCache *cache.Cache, cloudData []cloudmodel.LBListener) *LBListener {
	updater := &LBListener{
		newUpdaterBase[
			cloudmodel.LBListener,
			*diffbase.LBListener,
			*metadbmodel.LBListener,
			metadbmodel.LBListener,
			*message.AddedLBListeners,
			message.AddedLBListeners,
			message.AddNoneAddition,
			*message.UpdatedLBListener,
			message.UpdatedLBListener,
			*message.UpdatedLBListenerFields,
			message.UpdatedLBListenerFields,
			*message.DeletedLBListeners,
			message.DeletedLBListeners,
			message.DeleteNoneAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN,
			wholeCache,
			db.NewLBListener().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.LBListeners,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (l *LBListener) generateDBItemToAdd(cloudItem *cloudmodel.LBListener) (*metadbmodel.LBListener, bool) {
	lbID, exists := l.cache.ToolDataSet.GetLBIDByLcuuid(cloudItem.LBLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_LB_EN, cloudItem.LBLcuuid,
			ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, cloudItem.Lcuuid,
		), l.metadata.LogPrefixes)
		return nil, false
	}

	dbItem := &metadbmodel.LBListener{
		Name:     cloudItem.Name,
		LBID:     lbID,
		IPs:      cloudItem.IPs,
		SNATIPs:  cloudItem.SNATIPs,
		Label:    cloudItem.Label,
		Port:     cloudItem.Port,
		Protocol: cloudItem.Protocol,
		Domain:   l.metadata.GetDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (l *LBListener) generateUpdateInfo(diffBase *diffbase.LBListener, cloudItem *cloudmodel.LBListener) (*message.UpdatedLBListenerFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedLBListenerFields)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.IPs != cloudItem.IPs {
		mapInfo["ips"] = cloudItem.IPs
		structInfo.IPs.Set(diffBase.IPs, cloudItem.IPs)
	}
	if diffBase.SNATIPs != cloudItem.SNATIPs {
		mapInfo["snat_ips"] = cloudItem.SNATIPs
		structInfo.SNATIPs.Set(diffBase.SNATIPs, cloudItem.SNATIPs)
	}
	if diffBase.Port != cloudItem.Port {
		mapInfo["port"] = cloudItem.Port
		structInfo.Port.Set(diffBase.Port, cloudItem.Port)
	}
	if diffBase.Protocol != cloudItem.Protocol {
		mapInfo["protocol"] = cloudItem.Protocol
		structInfo.Protocol.Set(diffBase.Protocol, cloudItem.Protocol)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
