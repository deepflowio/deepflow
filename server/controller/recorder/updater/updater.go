/*
 * Copyright (c) 2023 Yunshan Networks
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
	"reflect"

	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/listener"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	msg "github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/constraint"
)

// ResourceUpdater 实现资源进行新旧数据比对，并根据比对结果增删改资源
type ResourceUpdater interface {
	// 以资源的 lcuuid 为 key ，逐一检查 cloud 数据
	// 若 cache 的 diff base 中不存在，则添加
	// 若 cache 的 diff base 中存在，基于可更新字段，检查 cloud 数据是否发生变化，若发生变化，则更新；
	// 无论已存在资源有无变化，根据 cache 的 sequence 更新的 diff base 中的 sequence，用于标记资源是否需要被删除
	HandleAddAndUpdate()
	// 逐一检查 diff base 中的资源，若 sequence 不等于 cache 中的 sequence，则删除
	HandleDelete()

	Publisher
}

type Publisher interface {
	GetChanged() bool
	GetResourceType() string
	GetMySQLModelString() []string
}

type DataGenerator[CT constraint.CloudModel, MT constraint.MySQLModel, BT constraint.DiffBase, MFUPT msg.FieldsUpdatePtr[MFUT], MFUT msg.FieldsUpdate] interface {
	// 根据 cloud 数据获取对应的 diff base 数据
	getDiffBaseByCloudItem(*CT) (BT, bool)
	// 生成插入 DB 所需的数据
	generateDBItemToAdd(*CT) (*MT, bool)
	// 生产更新 DB 所需的数据
	generateUpdateInfo(BT, *CT) (MFUPT, map[string]interface{}, bool)
}

type UpdaterBase[
	CT constraint.CloudModel,
	MT constraint.MySQLModel,
	BT constraint.DiffBase,
	MAPT msg.AddPtr[MAT],
	MAT msg.Add,
	MUPT msg.UpdatePtr[MUT],
	MUT msg.Update,
	MFUPT msg.FieldsUpdatePtr[MFUT],
	MFUT msg.FieldsUpdate,
	MDPT msg.DeletePtr[MDT],
	MDT msg.Delete,
] struct {
	resourceType string

	cache             *cache.Cache                           // 基于 Domain 或者 SubDomain 范围构造
	domainToolDataSet *tool.DataSet                          // 基于 Domain 构造，仅当 Updater 资源属于 SubDomain 时使用
	dbOperator        db.Operator[MT]                        // 数据库操作对象
	diffBaseData      map[string]BT                          // 用于比对的旧资源数据
	cloudData         []CT                                   // 定时获取的新资源数据
	dataGenerator     DataGenerator[CT, MT, BT, MFUPT, MFUT] // 提供各类数据生成的方法

	listeners []listener.Listener[CT, MT, BT]                                     // 关注 Updater 的增删改操作行为及详情的监听器
	pubsub    pubsub.ResourcePubSub[MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT] // 用于发布订阅的消息中心

	// Set Changed to true if the resource database and cache are updated,
	// used for cache update notifications to trisolaris module.
	Changed bool
}

func newUpdaterBase[
	CT constraint.CloudModel,
	MT constraint.MySQLModel,
	BT constraint.DiffBase,
	MAPT msg.AddPtr[MAT],
	MAT msg.Add,
	MUPT msg.UpdatePtr[MUT],
	MUT msg.Update,
	MFUPT msg.FieldsUpdatePtr[MFUT],
	MFUT msg.FieldsUpdate,
	MDPT msg.DeletePtr[MDT],
	MDT msg.Delete,
](
	resourceType string, cache *cache.Cache, dbOperator db.Operator[MT], diffBaseData map[string]BT, cloudData []CT,
) UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT] {
	u := UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]{
		resourceType: resourceType,
		cache:        cache,
		dbOperator:   dbOperator,
		diffBaseData: diffBaseData,
		cloudData:    cloudData,
	}
	u.initPubSub()
	return u
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) initPubSub() {
	ps := pubsub.GetPubSub(pubsub.ResourceTypeToPubsubType[u.resourceType])
	if ps == nil {
		log.Errorf("pubsub not found for resource type: %s", u.resourceType)
		return
	}
	u.pubsub = ps.(pubsub.ResourcePubSub[MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT])
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) setDataGenerator(dataGenerator DataGenerator[CT, MT, BT, MFUPT, MFUT]) {
	u.dataGenerator = dataGenerator
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) setDomainToolDataSet(domainToolDataSet *tool.DataSet) {
	u.domainToolDataSet = domainToolDataSet
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) HandleAddAndUpdate() {
	dbItemsToAdd := []*MT{}
	logDebug := logDebugResourceTypeEnabled(u.resourceType)
	for _, cloudItem := range u.cloudData {
		if logDebug {
			log.Infof(debugCloudItem(u.resourceType, cloudItem))
		}
		diffBase, exists := u.dataGenerator.getDiffBaseByCloudItem(&cloudItem)
		if !exists {
			log.Infof("to add (cloud item: %#v)", cloudItem)
			dbItem, ok := u.dataGenerator.generateDBItemToAdd(&cloudItem)
			if ok {
				dbItemsToAdd = append(dbItemsToAdd, dbItem)
			}
		} else {
			diffBase.SetSequence(u.cache.GetSequence())
			infoStruct, infoMap, ok := u.dataGenerator.generateUpdateInfo(diffBase, &cloudItem)
			if ok {
				log.Infof("to update (cloud item: %#v, diff base item: %#v)", cloudItem, diffBase)
				u.update(&cloudItem, diffBase, infoMap, infoStruct)
			}
		}
	}
	if len(dbItemsToAdd) > 0 {
		u.add(dbItemsToAdd)
	}
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) HandleDelete() {
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

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) GetChanged() bool {
	return u.Changed
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) GetResourceType() string {
	return u.resourceType
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) GetMySQLModelString() []string { // TODO delete
	var mt MT
	return []string{reflect.TypeOf(mt).String()}
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) add(dbItemsToAdd []*MT) {
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

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) addPage(dbItemsToAdd []*MT) {
	if dbItems, ok := u.dbOperator.AddBatch(dbItemsToAdd); ok {
		u.notifyOnAdded(dbItems)

		msgData := MAPT(new(MAT))
		msgData.SetMySQLItems(dbItems)
		log.Infof("add %s msg data: %#v", u.resourceType, msgData)
		if u.pubsub != nil {
			u.pubsub.PublishBatchAdded(msgData)
		}
		u.Changed = true
	}
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) update(cloudItem *CT, diffBase BT, info map[string]interface{}, fields MFUPT) {
	if dbItem, ok := u.dbOperator.Update(diffBase.GetLcuuid(), info); ok {
		u.notifyOnUpdated(cloudItem, diffBase)
		log.Infof("fields: %#v", fields)
		log.Infof("db item: %#v", dbItem)

		fields.SetID((*dbItem).GetID())
		fields.SetLcuuid(diffBase.GetLcuuid())
		msgData := MUPT(new(MUT))
		msgData.SetFields(fields)
		// msgData.SetID((*dbItem).GetID())
		// msgData.SetLcuuid(diffBase.GetLcuuid())
		log.Infof("update %s msg data fields: %#v", u.resourceType, msgData.GetFields())
		msgData.SetDiffBase(diffBase)
		msgData.SetCloudItem(cloudItem)
		log.Infof("update %s msg data: %#v", u.resourceType, msgData)
		if u.pubsub != nil {
			u.pubsub.PublishUpdated(msgData)
		}
		u.Changed = true
	}
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) delete(lcuuids []string) {
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

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) deletePage(lcuuids []string) {
	if dbItems, ok := u.dbOperator.DeleteBatch(lcuuids); ok {
		u.notifyOnDeleted(lcuuids)

		msgData := MDPT(new(MDT))
		msgData.SetLcuuids(lcuuids)
		msgData.SetMySQLItems(dbItems)
		log.Infof("delete %s msg data: %#v", u.resourceType, *msgData)
		if u.pubsub != nil {
			u.pubsub.PublishBatchDeleted(msgData)
		}
		u.Changed = true
	}
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) RegisterListener(listener listener.Listener[CT, MT, BT]) ResourceUpdater {
	u.listeners = append(u.listeners, listener)
	return u
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) notifyOnAdded(addedDBItems []*MT) {
	for _, l := range u.listeners {
		l.OnUpdaterAdded(addedDBItems)
	}
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) notifyOnUpdated(cloudItem *CT, diffBaseItem BT) {
	for _, l := range u.listeners {
		l.OnUpdaterUpdated(cloudItem, diffBaseItem)
	}
}

func (u *UpdaterBase[CT, MT, BT, MAPT, MAT, MUPT, MUT, MFUPT, MFUT, MDPT, MDT]) notifyOnDeleted(lcuuids []string) {
	for _, l := range u.listeners {
		l.OnUpdaterDeleted(lcuuids)
	}
}
