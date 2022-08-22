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

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/constraint"
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
	setter           DBItemSetter[MT]
}

func (o *OperatorBase[MT]) AddBatch(dbItems []*MT) ([]*MT, bool) {
	dbItemsToAdd, lcuuids, ok := o.formatDBItemsToAdd(dbItems)
	if !ok || len(dbItemsToAdd) == 0 {
		return nil, false
	}
	err := mysql.Db.Create(&dbItemsToAdd).Error
	if err != nil {
		log.Errorf("add %s batch failed: %v", o.resourceTypeName, err)
		log.Errorf("add %s (lcuuids: %v) failed", o.resourceTypeName, lcuuids)
		return nil, false
	}
	for _, dbItem := range dbItemsToAdd {
		log.Infof("add %s (detail: %+v) success", o.resourceTypeName, dbItem)
	}
	return dbItemsToAdd, true
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
	err := mysql.Db.Where("lcuuid IN ?", lcuuids).Delete(new(MT)).Error
	if err != nil {
		log.Errorf("delete %s (lcuuids: %v) failed: %v", o.resourceTypeName, lcuuids, err)
		return false
	}
	if o.softDelete {
		log.Infof("update %s (lcuuids: %v) deleted_at success", o.resourceTypeName, lcuuids)
	} else {
		log.Infof("delete %s (lcuuids: %v) success", o.resourceTypeName, lcuuids)
	}
	return true
}

// 在插入DB前检查是否有lcuuid重复的数据：
// 待入库数据本身有lcuuid重复：仅取1条数据入库。
// 与DB已存数据lcuuid重复：
// 		若资源有软删除需求，将lcuuid存在的数据ID赋值给新数据，删除旧数据，新数据入库；
// 		若资源无软删除需求，记录lcuuid重复异常，筛掉异常数据，剩余数据入库。
func (o *OperatorBase[MT]) formatDBItemsToAdd(dbItems []*MT) (dbItemsToAdd []*MT, lcuuidsToAdd []string, ok bool) {
	dupCloudLcuuids := []string{}
	lcuuids := make([]string, 0, len(dbItems))
	lcuuidToDBItem := make(map[string]*MT)
	dedupItems := []*MT{}
	for _, dbItem := range dbItems {
		lcuuid := (*dbItem).GetLcuuid()
		if common.Contains(lcuuids, lcuuid) && !common.Contains(dupCloudLcuuids, lcuuid) {
			dupCloudLcuuids = append(dupCloudLcuuids, lcuuid)
		} else {
			lcuuids = append(lcuuids, lcuuid)
			lcuuidToDBItem[lcuuid] = dbItem
			dedupItems = append(dedupItems, dbItem)
		}
	}
	if len(dupCloudLcuuids) != 0 {
		log.Errorf("%s data is duplicated in cloud data (lcuuids: %v)", o.resourceTypeName, dupCloudLcuuids)
	}
	dbItems = dedupItems

	var dupLcuuidDBItems []*MT
	err := mysql.Db.Unscoped().Where("lcuuid IN ?", lcuuids).Find(&dupLcuuidDBItems).Error
	if err != nil {
		log.Errorf("get %s duplicate data failed: %v", o.resourceTypeName, err)
		return
	}

	if len(dupLcuuidDBItems) != 0 {
		if !o.softDelete {
			dupLcuuids := make([]string, 0, len(dupLcuuidDBItems))
			for _, dupLcuuidDBItem := range dupLcuuidDBItems {
				lcuuid := (*dupLcuuidDBItem).GetLcuuid()
				if !common.Contains(dupLcuuids, lcuuid) {
					dupLcuuids = append(dupLcuuids, lcuuid)
				}
			}
			log.Errorf("%s data is duplicated with db data (lcuuids: %v)", o.resourceTypeName, dupLcuuids)

			num := len(lcuuids) - len(dupLcuuids)
			dbItemsToAdd := make([]*MT, 0, num)
			lcuuidsToAdd := make([]string, 0, num)
			for lcuuid, dbItem := range lcuuidToDBItem {
				if !common.Contains(dupLcuuids, lcuuid) {
					dbItemsToAdd = append(dbItemsToAdd, dbItem)
					lcuuidsToAdd = append(lcuuidsToAdd, lcuuid)
				}
			}
			return dbItemsToAdd, lcuuidsToAdd, true
		} else {
			for _, dupLcuuidDBItem := range dupLcuuidDBItems {
				dbItem, exists := lcuuidToDBItem[(*dupLcuuidDBItem).GetLcuuid()]
				if !exists {
					continue
				}
				o.setter.setDBItemID(dbItem, (*dupLcuuidDBItem).GetID())
			}
			err = mysql.Db.Unscoped().Delete(&dupLcuuidDBItems).Error
			if err != nil {
				log.Errorf("%s lcuuid duplicated (lcuuids:)", o.resourceTypeName)
				return dbItems, lcuuids, true
			}
		}
	}
	return dbItems, lcuuids, true
}
