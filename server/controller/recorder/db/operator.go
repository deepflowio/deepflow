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

package db

import (
	"fmt"
	"slices"

	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	rcommon "github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db/idmng"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("recorder.db")

type Operator[MPT metadbmodel.AssetResourceConstraintPtr[MT], MT metadbmodel.AssetResourceConstraint] interface {
	// 批量插入数据
	AddBatch(dbItems []*MT) ([]*MT, bool)
	// 更新数据
	Update(lcuuid string, updateInfo map[string]interface{}) (*MT, bool)
	// 批量删除数据
	DeleteBatch(lcuuids []string) ([]*MT, bool)

	GetSoftDelete() bool
}

type OperatorBase[MPT metadbmodel.AssetResourceConstraintPtr[MT], MT metadbmodel.AssetResourceConstraint] struct {
	metadata *rcommon.Metadata

	resourceTypeName        string
	softDelete              bool
	allocateID              bool
	fieldsNeededAfterCreate []string // fields needed to be used after create

	// whether convert models to loggable models, default is false
	toLoggable bool
}

func newOperatorBase[MPT metadbmodel.AssetResourceConstraintPtr[MT], MT metadbmodel.AssetResourceConstraint](resourceTypeName string, softDelete, allocateID bool) OperatorBase[MPT, MT] {
	return OperatorBase[MPT, MT]{
		resourceTypeName: resourceTypeName,
		softDelete:       softDelete,
		allocateID:       allocateID,
	}
}

func (o *OperatorBase[MPT, MT]) SetMetadata(md *rcommon.Metadata) Operator[MPT, MT] {
	o.metadata = md
	return o
}

func (o *OperatorBase[MPT, MT]) GetSoftDelete() bool {
	return o.softDelete
}

func (o *OperatorBase[MPT, MT]) setFieldsNeededAfterCreate(fs []string) {
	o.fieldsNeededAfterCreate = fs
}

func (o *OperatorBase[MPT, MT]) AddBatch(items []*MT) ([]*MT, bool) {
	itemsToAdd, lcuuidsToAdd, allocatedIDs, ok := o.formatItemsToAdd(items)
	if !ok || len(itemsToAdd) == 0 {
		return nil, false
	}

	err := o.metadata.DB.Create(&itemsToAdd).Error
	if err != nil {
		log.Errorf("%s batch failed: %v", rcommon.LogAdd(o.resourceTypeName), err.Error(), o.metadata.LogPrefixes)
		log.Errorf("%s (lcuuids: %v) failed", rcommon.LogAdd(o.resourceTypeName), lcuuidsToAdd, o.metadata.LogPrefixes)

		if o.allocateID && len(allocatedIDs) > 0 {
			idmng.ReleaseIDs(o.metadata.GetORGID(), o.resourceTypeName, allocatedIDs)
		}
		return nil, false
	}
	// If MySQL is not configured with auto_increment_increment=1, maybe 2 for HA or other reasons.
	// When use gorm to insert batch data, it will fill the ids of the created items with increment by 1 not 2.
	// Setting tag autoIncrementIncrement:2 can make it correct, but hardcoding doesn't work for all possible values.
	// So we need to get the created items manually to make sure ids are correct when following situations all happen:
	// 		1. MySQL is not configured with auto_increment_increment=1
	// 		2. We need to use the ids of the created items
	// 		3. Ids are not allocated by ourselves
	// 		4. Use gorm to insert batch data
	if metadb.GetConfig().GetAutoIncrementIncrement() != 1 && len(o.fieldsNeededAfterCreate) != 0 && !o.allocateID && len(lcuuidsToAdd) > 1 {
		o.metadata.DB.Select(o.fieldsNeededAfterCreate).Where("lcuuid IN ?", lcuuidsToAdd).Find(&itemsToAdd)
	}

	for _, item := range itemsToAdd {
		log.Infof("%s (detail: %+v) success", rcommon.LogAdd(o.resourceTypeName), rcommon.ToLoggable(o.toLoggable, item), o.metadata.LogPrefixes)
	}

	return itemsToAdd, true
}

func (o *OperatorBase[MPT, MT]) Update(lcuuid string, updateInfo map[string]interface{}) (*MT, bool) {
	dbItem := new(MT)
	err := o.metadata.DB.Model(&dbItem).Where("lcuuid = ?", lcuuid).Updates(updateInfo).Error
	if err != nil {
		log.Errorf("%s (lcuuid: %s, detail: %+v) failed: %s", rcommon.LogUpdate(o.resourceTypeName), lcuuid, updateInfo, err.Error(), o.metadata.LogPrefixes)
		return dbItem, false
	}
	log.Infof("%s (lcuuid: %s, detail: %+v) success", rcommon.LogUpdate(o.resourceTypeName), lcuuid, rcommon.ToLoggable(o.toLoggable, updateInfo), o.metadata.LogPrefixes)
	o.metadata.DB.Model(&dbItem).Where("lcuuid = ?", lcuuid).Find(&dbItem)
	return dbItem, true
}

func (o *OperatorBase[MPT, MT]) DeleteBatch(lcuuids []string) ([]*MT, bool) {
	var deletedItems []*MT
	err := o.metadata.DB.Where("lcuuid IN ?", lcuuids).Find(&deletedItems).Error
	if err != nil {
		log.Errorf("%s (lcuuids: %v) failed: %v", rcommon.LogDelete(o.resourceTypeName), lcuuids, err.Error(), o.metadata.LogPrefixes)
		return nil, false
	}
	if len(deletedItems) == 0 {
		log.Warningf("%s (lcuuids: %v) no data need to delete", rcommon.LogDelete(o.resourceTypeName), lcuuids, o.metadata.LogPrefixes)
		return nil, true
	}
	err = o.metadata.DB.Delete(&deletedItems).Error
	if err != nil {
		log.Errorf("%s (lcuuids: %v) failed: %v", rcommon.LogDelete(o.resourceTypeName), lcuuids, err.Error(), o.metadata.LogPrefixes)
		return nil, false
	}
	if o.softDelete {
		log.Infof("%s (lcuuids: %v) deleted_at success", rcommon.LogUpdate(o.resourceTypeName), lcuuids, o.metadata.LogPrefixes)
	} else {
		log.Infof("%s (lcuuids: %v) success", rcommon.LogDelete(o.resourceTypeName), lcuuids, o.metadata.LogPrefixes)
	}

	o.returnUsedIDs(deletedItems)
	return deletedItems, true
}

func (o *OperatorBase[MPT, MT]) formatItemsToAdd(items []*MT) ([]*MT, []string, []int, bool) {
	// 待入库数据本身有lcuuid重复：仅取1条数据入库。
	items, lcuuids, lcuuidToDBItem := o.dedupInSelf(items)
	// 与DB已存数据lcuuid重复：
	// 		若资源有软删除需求，将lcuuid存在的数据ID赋值给新数据，删除旧数据，新数据入库；
	// 		若资源无软删除需求，记录lcuuid重复异常，筛掉异常数据，剩余数据入库。
	items, lcuuids, ok := o.dedupInDB(items, lcuuids, lcuuidToDBItem)

	var allocatedIDs []int
	// 按需请求分配器分配资源ID
	// 批量分配，仅剩部分可用ID/分配失败，仅入库有ID的资源
	items, allocatedIDs, ok = o.requestIDs(items)
	return items, lcuuids, allocatedIDs, ok
}

func (o OperatorBase[MPT, MT]) dedupInSelf(items []*MT) ([]*MT, []string, map[string]*MT) {
	dedupItems := []*MT{}
	lcuuids := []string{}
	lcuuidToItem := make(map[string]*MT)
	for _, item := range items {
		lcuuid := MPT(item).GetLcuuid()
		if slices.Contains(lcuuids, lcuuid) {
			log.Infof("%s data is duplicated in cloud data (lcuuid: %s)", o.resourceTypeName, lcuuid, o.metadata.LogPrefixes)
		} else {
			dedupItems = append(dedupItems, item)
			lcuuids = append(lcuuids, lcuuid)
			lcuuidToItem[lcuuid] = item
		}
	}
	return dedupItems, lcuuids, lcuuidToItem
}

func (o OperatorBase[MPT, MT]) dedupInDB(items []*MT, lcuuids []string, lcuuidToItem map[string]*MT) ([]*MT, []string, bool) {
	var dupItems []*MT
	err := o.metadata.DB.Unscoped().Where("lcuuid IN ?", lcuuids).Find(&dupItems).Error
	if err != nil {
		log.Errorf("get %s duplicate data failed: %v", o.resourceTypeName, err.Error(), o.metadata.LogPrefixes)
		return nil, nil, false
	}

	// 以 lcuuid 为对比 key 检查待入库数据与 db 数据是否重复,日志记录 db 重复数据，删除 db 重复数据后插入待入库数据。
	// 若资源有手动分配 ID 需求，则复用 ID，将 db 数据的已分配 ID 赋值给待入库数据，保持 ID 分配池的正确性；若无，则不考虑 ID 复用。
	// 若资源支持软删，有 db 重复数据为正常现象，日志记录等级为 INFO；反之，日志记录等级为 ERROR
	if len(dupItems) != 0 {
		dupLcuuids := []string{}
		dupItemIDs := []int{}
		for _, dupItem := range dupItems {
			lcuuid := MPT(dupItem).GetLcuuid()
			id := MPT(dupItem).GetID()
			item, exists := lcuuidToItem[lcuuid]
			if !exists {
				continue
			}
			if !slices.Contains(dupLcuuids, lcuuid) {
				dupLcuuids = append(dupLcuuids, lcuuid)
				dupItemIDs = append(dupItemIDs, id)
			}
			if o.allocateID {
				MPT(item).SetID(id)
			}
		}
		msg := fmt.Sprintf("%s data is duplicated with db data (lcuuids: %v, ids: %v, count: %d, one detail: %+v), will learn again", o.resourceTypeName, dupLcuuids, dupItemIDs, len(dupItems), dupItems[0])
		if o.softDelete {
			log.Info(msg, o.metadata.LogPrefixes)
		} else {
			log.Error(msg, o.metadata.LogPrefixes)
		}
		err = o.metadata.DB.Unscoped().Delete(&dupItems).Error
		if err != nil {
			log.Errorf("%s duplicated data failed: %+v", rcommon.LogDelete(o.resourceTypeName), err.Error(), o.metadata.LogPrefixes)
			return items, lcuuids, false
		}
	}
	return items, lcuuids, true
}

func (o *OperatorBase[MPT, MT]) requestIDs(items []*MT) ([]*MT, []int, bool) {
	if o.allocateID {
		var count int
		itemsHasID := []*MT{}
		itemsHasNoID := []*MT{}
		for _, item := range items {
			if MPT(item).GetID() == 0 {
				count++
				itemsHasNoID = append(itemsHasNoID, item)
			} else {
				itemsHasID = append(itemsHasID, item)
			}
		}
		if count > 0 {
			ids, err := idmng.GetIDs(o.metadata.GetORGID(), o.resourceTypeName, count)
			if err != nil {
				log.Errorf("%s request ids failed", o.resourceTypeName, o.metadata.LogPrefixes)
				return itemsHasID, []int{}, false
			}
			for i, id := range ids {
				MPT(itemsHasNoID[i]).SetID(id)
				itemsHasID = append(itemsHasID, itemsHasNoID[i])
			}
			log.Infof("%s use ids: %v, expected count: %d, true count: %d", o.resourceTypeName, ids, count, len(ids), o.metadata.LogPrefixes)
			return itemsHasID, ids, true
		} else {
			log.Infof("%s not use any id", o.resourceTypeName, o.metadata.LogPrefixes)
			return itemsHasID, []int{}, true
		}
	}
	return items, []int{}, true
}

func (o *OperatorBase[MPT, MT]) returnUsedIDs(deletedItems []*MT) {
	// 非软删除资源，删除成功后，检查归还所分配的资源ID
	if !o.softDelete && o.allocateID {
		var ids []int
		for _, dbItem := range deletedItems {
			ids = append(ids, MPT(dbItem).GetID())
		}
		err := idmng.ReleaseIDs(o.metadata.GetORGID(), o.resourceTypeName, ids)
		if err != nil {
			log.Errorf("%s release ids: %v failed", o.resourceTypeName, ids, o.metadata.LogPrefixes)
		}
		log.Infof("%s return used ids: %v", o.resourceTypeName, ids, o.metadata.LogPrefixes)
	}
}
