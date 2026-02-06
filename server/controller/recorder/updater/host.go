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
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
)

// HostMessageFactory Host资源的消息工厂
type HostMessageFactory struct{}

func (f *HostMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedHosts{}
}

func (f *HostMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedHost{}
}

func (f *HostMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedHosts{}
}

func (f *HostMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedHostFields{}
}

type Host struct {
	UpdaterBase[
		cloudmodel.Host,
		*diffbase.Host,
		*metadbmodel.Host,
		metadbmodel.Host,
	]
}

func NewHost(wholeCache *cache.Cache, cloudData []cloudmodel.Host) *Host {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_HOST_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_HOST_EN, &HostMessageFactory{})
	}

	updater := &Host{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_HOST_EN,
			wholeCache,
			db.NewHost().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.Hosts,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

// 实现 DataGenerator 接口

func (h *Host) generateDBItemToAdd(cloudItem *cloudmodel.Host) (*metadbmodel.Host, bool) {
	dbItem := &metadbmodel.Host{
		Name:       cloudItem.Name,
		UID:        ctrlrcommon.GenerateResourceShortUUID(ctrlrcommon.RESOURCE_TYPE_HOST_EN),
		IP:         cloudItem.IP,
		Hostname:   cloudItem.Hostname,
		Type:       cloudItem.Type,
		HType:      cloudItem.HType,
		VCPUNum:    cloudItem.VCPUNum,
		MemTotal:   cloudItem.MemTotal,
		ExtraInfo:  cloudItem.ExtraInfo,
		UserName:   "root",
		UserPasswd: "deepflow",
		State:      ctrlrcommon.HOST_STATE_COMPLETE,
		AZ:         cloudItem.AZLcuuid,
		Region:     cloudItem.RegionLcuuid,
		Domain:     h.metadata.GetDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (h *Host) generateUpdateInfo(diffBase *diffbase.Host, cloudItem *cloudmodel.Host) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := &message.UpdatedHostFields{}
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.IP != cloudItem.IP {
		mapInfo["ip"] = cloudItem.IP
		structInfo.IP.Set(diffBase.IP, cloudItem.IP)
	}
	if diffBase.Hostname != cloudItem.Hostname {
		mapInfo["hostname"] = cloudItem.Hostname
		structInfo.Hostname.Set(diffBase.Hostname, cloudItem.Hostname)
	}
	if diffBase.HType != cloudItem.HType {
		mapInfo["htype"] = cloudItem.HType
		structInfo.HType.Set(diffBase.HType, cloudItem.HType)
	}
	if diffBase.VCPUNum != cloudItem.VCPUNum {
		mapInfo["vcpu_num"] = cloudItem.VCPUNum
		structInfo.VCPUNum.Set(diffBase.VCPUNum, cloudItem.VCPUNum)
	}
	if diffBase.MemTotal != cloudItem.MemTotal {
		mapInfo["mem_total"] = cloudItem.MemTotal
		structInfo.MemTotal.Set(diffBase.MemTotal, cloudItem.MemTotal)
	}
	if diffBase.ExtraInfo != cloudItem.ExtraInfo {
		mapInfo["extra_info"] = cloudItem.ExtraInfo
		structInfo.ExtraInfo.Set(diffBase.ExtraInfo, cloudItem.ExtraInfo)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
