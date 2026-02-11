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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/listener"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
	"github.com/deepflowio/deepflow/server/controller/recorder/statsd"
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
	StatsdBuilder
}

type Publisher interface {
	GetChanged() bool
	GetResourceType() string
}

type StatsdBuilder interface {
	BuildStatsd(statsd.Statsd) ResourceUpdater
}

type DataGenerator[CT constraint.CloudModel, MT metadbmodel.AssetResourceConstraint, BT constraint.DiffBase] interface {
	// 生成插入 DB 所需的数据
	generateDBItemToAdd(*CT) (*MT, bool)

	// 生成更新 DB 所需的数据
	// 返回: (更新字段信息, 数据库更新映射, 是否成功)
	generateUpdateInfo(BT, *CT) (types.UpdatedFields, map[string]interface{}, bool)
}

const (
	hookerBeforeDBAddPage = iota
	hookerAfterDBDeletePage
)

type UpdaterBase[
	CT constraint.CloudModel, // 云端数据模型
	BT constraint.DiffBase, // 差异基准数据
	MPT metadbmodel.AssetResourceConstraintPtr[MT], // 数据库模型指针
	MT metadbmodel.AssetResourceConstraint, // 数据库模型
] struct {
	// === 基础元数据 ===
	metadata    *common.Metadata
	msgMetadata *message.Metadata

	// === 统计收集 ===
	statsd statsd.Statsd

	// === 资源标识 ===
	resourceType string

	// === 数据管理 ===
	cache             *cache.Cache              // 基于 Domain 或者 SubDomain 范围构造
	domainToolDataSet *tool.DataSet             // 基于 Domain 构造，仅当 Updater 资源属于 SubDomain 时使用
	dbOperator        db.Operator[MPT, MT]      // 数据库操作对象
	diffBaseData      map[string]BT             // 用于比对的旧资源数据
	cloudData         []CT                      // 定时获取的新资源数据
	dataGenerator     DataGenerator[CT, MT, BT] // 提供各类数据生成的方法

	// === 扩展机制 ===
	hookers   map[int]interface{}             // 批量增删改的 hooker
	listeners []listener.Listener[CT, MT, BT] // 关注 Updater 的增删改操作行为及详情的监听器
	pubsub    pubsub.ResourcePubSub           // 用于发布订阅的消息中心

	// === 消息工厂 ===
	messageFactory MessageFactory // 消息创建工厂

	// === 状态管理 ===
	Changed    bool // Set Changed to true if the resource database and cache are updated
	toLoggable bool // whether convert models to loggable models, default is false
}

func newUpdaterBase[
	CT constraint.CloudModel,
	BT constraint.DiffBase,
	MPT metadbmodel.AssetResourceConstraintPtr[MT],
	MT metadbmodel.AssetResourceConstraint,
](
	resourceType string,
	cache *cache.Cache,
	dbOperator db.Operator[MPT, MT],
	diffBaseData map[string]BT,
	cloudData []CT,
) UpdaterBase[CT, BT, MPT, MT] {
	u := UpdaterBase[CT, BT, MPT, MT]{
		metadata: cache.GetMetadata(),

		resourceType: resourceType,
		cache:        cache,
		dbOperator:   dbOperator,
		diffBaseData: diffBaseData,
		cloudData:    cloudData,
		hookers:      make(map[int]interface{}),
	}

	// 初始化消息元数据
	u.msgMetadata = message.NewMetadata(
		message.MetadataPlatform(u.metadata.Platform),
		message.MetadataSoftDelete(u.dbOperator.GetSoftDelete()),
		message.MetadataToolDataSet(cache.ToolDataSet),
	)

	// 获取消息工厂
	u.messageFactory = GetMessageFactory(resourceType)
	if u.messageFactory == nil {
		log.Errorf("message factory not found for resource type: %s", resourceType, u.metadata.LogPrefixes)
	}

	// 初始化发布订阅
	u.initPubSub()
	return u
}

func (u *UpdaterBase[CT, BT, MPT, MT]) initPubSub() {
	ps := pubsub.GetPubSub(u.resourceType)
	if ps == nil {
		log.Errorf("pubsub not found for resource type: %s", u.resourceType, u.metadata.LogPrefixes)
		return
	}
	u.pubsub = ps.(pubsub.ResourcePubSub)
}

func (u *UpdaterBase[CT, BT, MPT, MT]) BuildStatsd(statsd statsd.Statsd) ResourceUpdater {
	u.statsd = statsd
	return u
}

func (u *UpdaterBase[CT, BT, MPT, MT]) setDataGenerator(dataGenerator DataGenerator[CT, MT, BT]) {
	u.dataGenerator = dataGenerator
}

func (u *UpdaterBase[CT, BT, MPT, MT]) setDomainToolDataSet(domainToolDataSet *tool.DataSet) {
	u.domainToolDataSet = domainToolDataSet
}

func (u *UpdaterBase[CT, BT, MPT, MT]) RegisterListener(listener listener.Listener[CT, MT, BT]) ResourceUpdater {
	u.listeners = append(u.listeners, listener)
	return u
}

func (u *UpdaterBase[CT, BT, MPT, MT]) GetResourceType() string {
	return u.resourceType
}

func (u *UpdaterBase[CT, BT, MPT, MT]) GetChanged() bool {
	return u.Changed
}

// 核心业务方法实现

func (u *UpdaterBase[CT, BT, MPT, MT]) HandleAddAndUpdate() {
	dbItemsToAdd := []*MT{}
	logDebug := logDebugResourceTypeEnabled(u.resourceType)

	for _, cloudItem := range u.cloudData {
		if logDebug {
			log.Info(debugCloudItem(u.resourceType, cloudItem), u.metadata.LogPrefixes)
		}

		diffBase, exists := u.diffBaseData[cloudItem.GetLcuuid()]
		if !exists {
			// 新增逻辑
			log.Infof("to %s (cloud item: %#v)", common.LogAdd(u.resourceType), common.ToLoggable(u.toLoggable, cloudItem), u.metadata.LogPrefixes)
			dbItem, ok := u.dataGenerator.generateDBItemToAdd(&cloudItem)
			if ok {
				dbItemsToAdd = append(dbItemsToAdd, dbItem)
			}
		} else {
			// 更新逻辑
			diffBase.SetSequence(u.cache.GetSequence())
			structInfo, mapInfo, ok := u.dataGenerator.generateUpdateInfo(diffBase, &cloudItem)
			if ok {
				log.Infof("to %s (cloud item: %#v, diff base item: %#v)", common.LogUpdate(u.resourceType), common.ToLoggable(u.toLoggable, cloudItem), common.ToLoggable(u.toLoggable, diffBase), u.metadata.LogPrefixes)
				u.update(&cloudItem, diffBase, mapInfo, structInfo)
			}
		}
	}

	if len(dbItemsToAdd) > 0 {
		u.add(dbItemsToAdd)
	}
}

func (u *UpdaterBase[CT, BT, MPT, MT]) HandleDelete() {
	lcuuidsOfBatchToDelete := []string{}
	for lcuuid, diffBase := range u.diffBaseData {
		if diffBase.GetSequence() != u.cache.GetSequence() {
			log.Infof("to %s (diff base item: %#v)", common.LogDelete(u.resourceType), common.ToLoggable(u.toLoggable, diffBase), u.metadata.LogPrefixes)
			lcuuidsOfBatchToDelete = append(lcuuidsOfBatchToDelete, lcuuid)
		}
	}
	if len(lcuuidsOfBatchToDelete) > 0 {
		u.delete(lcuuidsOfBatchToDelete)
	}
}

// 私有方法实现

func (u *UpdaterBase[CT, BT, MPT, MT]) add(dbItemsToAdd []*MT) {
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

func (u *UpdaterBase[CT, BT, MPT, MT]) addPage(dbItemsToAdd []*MT) {
	var addition interface{} // 简化为 interface{}，由具体实现处理

	// 执行前置钩子（如果存在）
	if hooker, ok := u.hookers[hookerBeforeDBAddPage]; ok {
		log.Infof("start to run %s beforeAddPage hooker", u.resourceType, u.metadata.LogPrefixes)

		// 类型断言处理钩子，这里需要根据具体资源类型进行适配
		// 暂时使用interface{}，后续可以优化
		if h, ok := hooker.(interface {
			beforeAddPage([]*MT) ([]*MT, interface{}, bool)
		}); ok {
			var success bool
			dbItemsToAdd, addition, success = h.beforeAddPage(dbItemsToAdd)
			if !success {
				log.Errorf("%s failed to run hooker beforeAddPage", u.resourceType, u.metadata.LogPrefixes)
				return
			}
		}
	}

	// 执行数据库批量插入
	if dbItems, ok := u.dbOperator.AddBatch(dbItemsToAdd); ok {
		// 通知监听器
		u.notifyOnAdded(dbItems)

		// 发布消息
		if u.messageFactory != nil {
			msgData := u.messageFactory.CreateAddedMessage()
			msgData.SetMetadbItems(dbItems)
			if addition != nil {
				msgData.SetAddition(addition)
			}
			u.pubsub.PublishBatchAdded(u.msgMetadata, msgData)
		}

		u.Changed = true
	}
}

func (u *UpdaterBase[CT, BT, MPT, MT]) update(cloudItem *CT, diffBase BT, mapInfo map[string]interface{}, structInfo types.UpdatedFields) {
	if dbItem, ok := u.dbOperator.Update(diffBase.GetLcuuid(), mapInfo); ok {
		// 通知监听器
		u.notifyOnUpdated(cloudItem, diffBase)

		// 设置更新字段信息
		structInfo.SetID(MPT(dbItem).GetID())
		structInfo.SetLcuuid(diffBase.GetLcuuid())

		// 发布消息
		if u.messageFactory != nil {
			msgData := u.messageFactory.CreateUpdatedMessage()
			msgData.SetFields(structInfo)
			msgData.SetNewMetadbItem(dbItem)
			u.pubsub.PublishUpdated(u.msgMetadata, msgData)
		}

		u.Changed = true
	}
}

func (u *UpdaterBase[CT, BT, MPT, MT]) delete(lcuuids []string) {
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

func (u *UpdaterBase[CT, BT, MPT, MT]) deletePage(lcuuids []string) {
	if dbItems, ok := u.dbOperator.DeleteBatch(lcuuids); ok {
		// 通知监听器
		u.notifyOnDeleted(lcuuids, dbItems)

		var addition interface{}

		// 执行后置钩子（如果存在）
		if hooker, ok := u.hookers[hookerAfterDBDeletePage]; ok {
			log.Infof("start to run %s afterDeletePage hooker", u.resourceType, u.metadata.LogPrefixes)

			// 类型断言处理钩子
			if h, ok := hooker.(interface {
				afterDeletePage([]*MT) (interface{}, bool)
			}); ok {
				var success bool
				addition, success = h.afterDeletePage(dbItems)
				if !success {
					log.Errorf("%s failed to run hooker afterDeletePage", u.resourceType, u.metadata.LogPrefixes)
				}
			}
		}

		// 发布消息
		if u.messageFactory != nil {
			msgData := u.messageFactory.CreateDeletedMessage()
			msgData.SetLcuuids(lcuuids)
			msgData.SetMetadbItems(dbItems)
			if addition != nil {
				msgData.SetAddition(addition)
			}
			u.pubsub.PublishBatchDeleted(u.msgMetadata, msgData)
		}

		u.Changed = true
	}
}

// 监听器通知方法

func (u *UpdaterBase[CT, BT, MPT, MT]) notifyOnAdded(addedDBItems []*MT) {
	for _, l := range u.listeners {
		l.OnUpdaterAdded(addedDBItems)
	}
}

func (u *UpdaterBase[CT, BT, MPT, MT]) notifyOnUpdated(cloudItem *CT, diffBaseItem BT) {
	for _, l := range u.listeners {
		l.OnUpdaterUpdated(cloudItem, diffBaseItem)
	}
}

func (u *UpdaterBase[CT, BT, MPT, MT]) notifyOnDeleted(lcuuids []string, deletedDBItems []*MT) {
	for _, l := range u.listeners {
		l.OnUpdaterDeleted(lcuuids, deletedDBItems)
	}
}
