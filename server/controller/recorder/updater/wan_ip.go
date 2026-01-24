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
	"strings"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
)

// WANIPMessageFactory WANIP资源的消息工厂
type WANIPMessageFactory struct{}

func (f *WANIPMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedWANIPs{}
}

func (f *WANIPMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedWANIP{}
}

func (f *WANIPMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedWANIPs{}
}

func (f *WANIPMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedWANIPFields{}
}

type WANIP struct {
	UpdaterBase[
		cloudmodel.IP,
		*diffbase.WANIP,
		*metadbmodel.WANIP,
		metadbmodel.WANIP,
	]
}

func NewWANIP(wholeCache *cache.Cache, domainToolDataSet *tool.DataSet) *WANIP {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, &WANIPMessageFactory{})
	}

	updater := &WANIP{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN,
			wholeCache,
			db.NewWANIP().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.WANIPs,
			[]cloudmodel.IP(nil),
		),
	}
	updater.setDomainToolDataSet(domainToolDataSet)
	updater.setDataGenerator(updater)
	return updater
}

func (i *WANIP) SetCloudData(cloudData []cloudmodel.IP) {
	i.cloudData = cloudData
}

func (i *WANIP) generateDBItemToAdd(cloudItem *cloudmodel.IP) (*metadbmodel.WANIP, bool) {
	vinterfaceID, exists := i.cache.ToolDataSet.GetVInterfaceIDByLcuuid(cloudItem.VInterfaceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.VInterfaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, cloudItem.Lcuuid,
		), i.metadata.LogPrefixes)
		return nil, false
	}
	var subnetID int

	ip := rcommon.FormatIP(cloudItem.IP)
	if ip == "" {
		log.Error(ipIsInvalid(
			ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, cloudItem.Lcuuid, cloudItem.IP,
		), i.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.WANIP{
		IP:           ip,
		Domain:       i.metadata.GetDomainLcuuid(),
		SubDomain:    cloudItem.SubDomainLcuuid,
		VInterfaceID: vinterfaceID,
		SubnetID:     subnetID,
		Region:       cloudItem.RegionLcuuid,
		ISP:          rcommon.WAN_IP_ISP,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	if strings.Contains(cloudItem.IP, ":") {
		dbItem.Netmask = rcommon.IPV6_DEFAULT_NETMASK
		dbItem.Gateway = rcommon.IPV6_DEFAULT_GATEWAY
	} else {
		dbItem.Netmask = rcommon.IPV4_DEFAULT_NETMASK
		dbItem.Gateway = rcommon.IPV4_DEFAULT_GATEWAY
	}
	return dbItem, true
}

func (i *WANIP) generateUpdateInfo(diffBase *diffbase.WANIP, cloudItem *cloudmodel.IP) (types.UpdatedFields, map[string]interface{}, bool) {
	// 创建具体的UpdatedWANIPFields，然后转换为接口类型
	structInfo := &message.UpdatedWANIPFields{}
	mapInfo := make(map[string]interface{})
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	// 返回接口类型
	return structInfo, mapInfo, len(mapInfo) > 0
}
