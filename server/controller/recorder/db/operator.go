/*
 * Copyright (c) 2022 Yunshan Networks
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
	"github.com/op/go-logging"
	"gorm.io/gorm/clause"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
)

var log = logging.MustGetLogger("recorder.db")

type Operator[MT constraint.MySQLModel] interface {
	// 批量插入数据
	AddBatch(dbItems []*MT) ([]*MT, bool)
	// 更新数据
	Update(lcuuid string, updateInfo map[string]interface{}) (*MT, bool)
	// 批量删除数据
	DeleteBatch(lcuuids []string) bool
}

// TODO 使用结构体而非结构体指针作为泛型类型，在需要对结构体value修改时十分不便，
// 使用指针时，初始化空结构体不便，reflect性能较差，不可高频使用；后续需要寻找方法解决
type DBItemSetter[MT constraint.MySQLModel] interface {
	setDBItemID(dbItem *MT, id int)
}

type OperatorBase[MT constraint.MySQLModel] struct {
	resourceTypeName string
	softDelete       bool
	allocateID       bool
	setter           DBItemSetter[MT]
}

func (o *OperatorBase[MT]) AddBatch(items []*MT) ([]*MT, bool) {
	itemsToAdd, lcuuidsToAdd, allocatedIDs, ok := o.formatItemsToAdd(items)
	if !ok || len(itemsToAdd) == 0 {
		return nil, false
	}

	err := mysql.Db.Create(&itemsToAdd).Error
	if err != nil {
		log.Errorf("add %s batch failed: %v", o.resourceTypeName, err)
		log.Errorf("add %s (lcuuids: %v) failed", o.resourceTypeName, lcuuidsToAdd)

		if o.allocateID && len(allocatedIDs) > 0 {
			ReleaseIDs(o.resourceTypeName, allocatedIDs)
		}
		return nil, false
	}
	for _, item := range itemsToAdd {
		log.Infof("add %s (detail: %+v) success", o.resourceTypeName, item)
	}

	return itemsToAdd, true
}

func (o *OperatorBase[MT]) Update(lcuuid string, updateInfo map[string]interface{}) (*MT, bool) {
	dbItem := new(MT)
	err := mysql.Db.Model(dbItem).Where("lcuuid = ?", lcuuid).Updates(updateInfo).Error
	if err != nil {
		log.Errorf("update %s (lcuuid: %s, detail: %+v) success", o.resourceTypeName, lcuuid, updateInfo, err)
		return dbItem, false
	}
	log.Infof("update %s (lcuuid: %s, detail: %+v) success", o.resourceTypeName, lcuuid, updateInfo)
	return dbItem, true
}

func (o *OperatorBase[MT]) DeleteBatch(lcuuids []string) bool {
	var deletedItems []*MT
	err := mysql.Db.Clauses(clause.Returning{}).Where("lcuuid IN ?", lcuuids).Delete(&deletedItems).Error
	if err != nil {
		log.Errorf("delete %s (lcuuids: %v) failed: %v", o.resourceTypeName, lcuuids, err)
		return false
	}
	if o.softDelete {
		log.Infof("update %s (lcuuids: %v) deleted_at success", o.resourceTypeName, lcuuids)
	} else {
		log.Infof("delete %s (lcuuids: %v) success", o.resourceTypeName, lcuuids)
	}

	o.returnUsedIDs(deletedItems)
	return true
}

func (o *OperatorBase[MT]) formatItemsToAdd(items []*MT) ([]*MT, []string, []int, bool) {
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

func (o OperatorBase[MT]) dedupInSelf(items []*MT) ([]*MT, []string, map[string]*MT) {
	dedupItems := []*MT{}
	lcuuids := []string{}
	lcuuidToItem := make(map[string]*MT)
	for _, item := range items {
		lcuuid := (*item).GetLcuuid()
		if common.Contains(lcuuids, lcuuid) {
			log.Infof("%s data is duplicated in cloud data (lcuuid: %s)", o.resourceTypeName, lcuuid)
		} else {
			dedupItems = append(dedupItems, item)
			lcuuids = append(lcuuids, lcuuid)
			lcuuidToItem[lcuuid] = item
		}
	}
	return dedupItems, lcuuids, lcuuidToItem
}

func (o OperatorBase[MT]) dedupInDB(items []*MT, lcuuids []string, lcuuidToItem map[string]*MT) ([]*MT, []string, bool) {
	var dupItems []*MT
	err := mysql.Db.Unscoped().Where("lcuuid IN ?", lcuuids).Find(&dupItems).Error
	if err != nil {
		log.Errorf("get %s duplicate data failed: %v", o.resourceTypeName, err)
		return nil, nil, false
	}

	if len(dupItems) != 0 {
		if o.softDelete {
			dupLcuuids := []string{}
			dupItemIDs := []int{}
			for _, dupItem := range dupItems {
				lcuuid := (*dupItem).GetLcuuid()
				id := (*dupItem).GetID()
				item, exists := lcuuidToItem[lcuuid]
				if !exists {
					continue
				}
				if !common.Contains(dupLcuuids, lcuuid) {
					dupLcuuids = append(dupLcuuids, lcuuid)
					dupItemIDs = append(dupItemIDs, id)
				}
				o.setter.setDBItemID(item, id)
				// (*dbItem).SetID((*dupItem).GetID()) // TODO 不可行
			}
			log.Infof("%s data is duplicated with db data (lcuuids: %v, ids: %v), will learn again", o.resourceTypeName, dupLcuuids, dupItemIDs)
			err = mysql.Db.Unscoped().Delete(&dupItems).Error
			if err != nil {
				log.Errorf("delete duplicated data failed: %+v", err)
				return items, lcuuids, false
			}
		} else {
			dupLcuuids := []string{}
			for _, dupItem := range dupItems {
				lcuuid := (*dupItem).GetLcuuid()
				if !common.Contains(dupLcuuids, lcuuid) {
					dupLcuuids = append(dupLcuuids, lcuuid)
				}
			}
			log.Errorf("%s data is duplicated with db data (lcuuids: %v)", o.resourceTypeName, dupLcuuids)

			count := len(lcuuids) - len(dupLcuuids)
			dedupItems := make([]*MT, 0, count)
			dedupLcuuids := make([]string, 0, count)
			for lcuuid, dbItem := range lcuuidToItem {
				if !common.Contains(dupLcuuids, lcuuid) {
					dedupItems = append(dedupItems, dbItem)
					dedupLcuuids = append(dedupLcuuids, lcuuid)
				}
			}
			return dedupItems, dedupLcuuids, true
		}
	}
	return items, lcuuids, true
}

func (o *OperatorBase[MT]) requestIDs(items []*MT) ([]*MT, []int, bool) {
	if o.allocateID {
		var count int
		itemsHasID := []*MT{}
		itemsHasNoID := []*MT{}
		for _, item := range items {
			if (*item).GetID() == 0 {
				count++
				itemsHasNoID = append(itemsHasNoID, item)
			} else {
				itemsHasID = append(itemsHasID, item)
			}
		}
		if count > 0 {
			ids, err := GetIDs(o.resourceTypeName, count)
			if err != nil {
				log.Errorf("%s request ids failed", o.resourceTypeName)
				return itemsHasID, []int{}, false
			}
			for i, id := range ids {
				o.setter.setDBItemID(itemsHasNoID[i], id)
				itemsHasID = append(itemsHasID, itemsHasNoID[i])
			}
			log.Infof("%s use ids: %v", o.resourceTypeName, ids)
			return itemsHasID, ids, true
		} else {
			log.Infof("%s not use any id", o.resourceTypeName)
			return itemsHasID, []int{}, true
		}
	}
	return items, []int{}, true
}

func (o *OperatorBase[MT]) returnUsedIDs(deletedItems []*MT) {
	// 非软删除资源，删除成功后，检查归还所分配的资源ID
	if !o.softDelete && o.allocateID {
		var ids []int
		for _, dbItem := range deletedItems {
			ids = append(ids, (*dbItem).GetID())
		}
		err := ReleaseIDs(o.resourceTypeName, ids)
		if err != nil {
			log.Errorf("%s release ids: %v failed", o.resourceTypeName, ids)
		}
		log.Infof("%s return used ids: %v", o.resourceTypeName, ids)
	}
}
