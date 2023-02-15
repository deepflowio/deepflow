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

package updater

import (
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

// ResourceUpdater 实现资源进行新旧数据比对，并根据比对结果增删改资源
type ResourceUpdater interface {
	// 以资源的lcuuid为key，逐一检查cloud数据
	// 若cache的diff base中不存在，则添加
	// 若cache的diff base中存在，基于可更新字段，检查cloud数据是否发生变化，若发生变化，则更新；
	// 无论已存在资源有无变化，根据cache的sequence更新的diff base中的sequence，用于标记资源是否需要被删除
	HandleAddAndUpdate()
	// 逐一检查diff base中的资源，若sequence不等于cache中的sequence，则删除
	HandleDelete()
}

type DataGenerator[CT constraint.CloudModel, MT constraint.MySQLModel, BT constraint.DiffBase[MT]] interface {
	// 根据cloud数据获取对应的diff base数据
	getDiffBaseByCloudItem(*CT) (BT, bool)
	// 生成插入DB所需的数据
	generateDBItemToAdd(*CT) (*MT, bool)
	// 生产更新DB所需的数据
	generateUpdateInfo(BT, *CT) (map[string]interface{}, bool)
}

type CacheHandler[CT constraint.CloudModel, MT constraint.MySQLModel, BT constraint.DiffBase[MT]] interface {
	// 根据新增的db数据，更新cache
	addCache([]*MT)
	// 根据更新的db数据，更新cache
	updateCache(*CT, BT)
	// 根据删除的db数据，更新cache
	deleteCache([]string)
}

type Callbacks[CT constraint.CloudModel, MT constraint.MySQLModel, BT constraint.DiffBase[MT]] struct {
	onAdded   func(addedDBItems []*MT)
	onUpdated func(cloudItem *CT, diffBaseItem BT)
	onDeleted func(lcuuids []string)
}

type UpdaterBase[CT constraint.CloudModel, MT constraint.MySQLModel, BT constraint.DiffBase[MT]] struct {
	cache             *cache.Cache              // 基于 Domain 或者 SubDomain 范围构造
	domainToolDataSet *cache.ToolDataSet        // TODO ugly 基于 Domain 构造，仅当 Updater 资源属于 SubDomain 时使用
	dbOperator        db.Operator[MT]           // 数据库操作对象
	diffBaseData      map[string]BT             // 用于比对的旧资源数据
	cloudData         []CT                      // 定时获取的新资源数据
	dataGenerator     DataGenerator[CT, MT, BT] // 提供各类数据生成的方法
	// TODO 移出updater
	cacheHandler CacheHandler[CT, MT, BT] // 提供处理cache中特定资源的方法
	callbacks    Callbacks[CT, MT, BT]
}

func (u *UpdaterBase[CT, MT, BT]) HandleAddAndUpdate() {
	dbItemsToAdd := []*MT{}
	for _, cloudItem := range u.cloudData {
		diffBase, exists := u.dataGenerator.getDiffBaseByCloudItem(&cloudItem)
		if !exists {
			log.Infof("to add (cloud item: %#v)", cloudItem)
			dbItem, ok := u.dataGenerator.generateDBItemToAdd(&cloudItem)
			if ok {
				dbItemsToAdd = append(dbItemsToAdd, dbItem)
			}
		} else {
			diffBase.SetSequence(u.cache.GetSequence())
			updateInfo, ok := u.dataGenerator.generateUpdateInfo(diffBase, &cloudItem)
			if ok {
				log.Infof("to update (cloud item: %#v, diff base item: %#v)", cloudItem, diffBase)
				u.update(&cloudItem, diffBase, updateInfo)
			}
		}
	}
	if len(dbItemsToAdd) > 0 {
		u.add(dbItemsToAdd)
	}
}

func (u *UpdaterBase[CT, MT, BT]) HandleDelete() {
	lcuuidsOfBatchToDelete := []string{}
	for lcuuid, diffBase := range u.diffBaseData {
		if diffBase.GetSequence() != u.cache.GetSequence() {
			log.Infof("to delete (diff base item: %#v)", diffBase)
			lcuuidsOfBatchToDelete = append(lcuuidsOfBatchToDelete, lcuuid)
		}
	}
	if len(lcuuidsOfBatchToDelete) > 0 {
		u.delete(lcuuidsOfBatchToDelete)
	}
}

func (u *UpdaterBase[CT, MT, BT]) RegisterCallbacks(onAdded func(addedDBItems []*MT), onUpdated func(cloudItem *CT, diffBaseItem BT), onDeleted func(lcuuids []string)) {
	u.callbacks.onAdded = onAdded
	u.callbacks.onUpdated = onUpdated
	u.callbacks.onDeleted = onDeleted
}

// 创建资源，按序操作DB、cache、资源变更事件
func (u *UpdaterBase[CT, MT, BT]) add(dbItemsToAdd []*MT) {
	count := len(dbItemsToAdd)
	offset := 1000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		u.addPage(dbItemsToAdd[start:end])
	}
}

func (u *UpdaterBase[CT, MT, BT]) addPage(dbItemsToAdd []*MT) {
	addedDBItems, ok := u.dbOperator.AddBatch(dbItemsToAdd)
	if ok {
		u.cacheHandler.addCache(addedDBItems)
		if u.callbacks.onAdded != nil {
			u.callbacks.onAdded(addedDBItems)
		}
	}
}

// 更新资源，按序操作DB、cache、资源变更事件
func (u *UpdaterBase[CT, MT, BT]) update(cloudItem *CT, diffBase BT, updateInfo map[string]interface{}) {
	_, ok := u.dbOperator.Update(diffBase.GetLcuuid(), updateInfo)
	if ok {
		if u.callbacks.onUpdated != nil {
			u.callbacks.onUpdated(cloudItem, diffBase)
		}
		u.cacheHandler.updateCache(cloudItem, diffBase)
	}
}

// 删除资源，按序操作DB、cache、资源变更事件
func (u *UpdaterBase[CT, MT, BT]) delete(lcuuids []string) {
	count := len(lcuuids)
	offset := 1000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		u.deletePage(lcuuids[start:end])
	}
}

func (u *UpdaterBase[CT, MT, BT]) deletePage(lcuuids []string) {
	if u.dbOperator.DeleteBatch(lcuuids) {
		if u.callbacks.onDeleted != nil {
			u.callbacks.onDeleted(lcuuids)
		}
		u.cacheHandler.deleteCache(lcuuids)
	}
}
