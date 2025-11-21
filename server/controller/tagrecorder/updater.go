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

package tagrecorder

import (
	"context"
	"time"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/query"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type UpdaterManager struct {
	tCtx                 context.Context
	tCancel              context.CancelFunc
	cfg                  config.ControllerConfig
	domainLcuuidToIconID map[string]int // TODO
	resourceTypeToIconID map[IconKey]int
}

func GetUpdaterManager() *UpdaterManager {
	updaterManagerOnce.Do(func() {
		updaterManager = &UpdaterManager{}
	})
	return updaterManager
}

func (u *UpdaterManager) Init(ctx context.Context, cfg config.ControllerConfig) {
	u.cfg = cfg
	u.tCtx, u.tCancel = context.WithCancel(ctx)
}

func (c *UpdaterManager) Start(sCtx context.Context) {
	log.Info("tagrecorder updater manager started")
	go func() {
		ticker := time.NewTicker(time.Duration(c.cfg.TagRecorderCfg.Interval) * time.Second)
		defer ticker.Stop()
	LOOP:
		for {
			select {
			case <-ticker.C:
				c.run()
			case <-sCtx.Done():
				break LOOP
			}
		}
	}()
}

func (t *UpdaterManager) Stop() {
	if t.tCancel != nil {
		t.tCancel()
	}
	log.Info("tagrecorder updater manager stopped")
}

func (c *UpdaterManager) run() {
	// 调用API获取资源对应的icon_id
	c.domainLcuuidToIconID, c.resourceTypeToIconID, _ = UpdateIconInfo(c.cfg)
	c.refresh()
}

func (c *UpdaterManager) refresh() {
	log.Info("tagrecorder updaters refresh")
	// 生成各资源更新器，刷新ch数据
	updaters := []Updater{
		NewChRegion(c.domainLcuuidToIconID, c.resourceTypeToIconID),
		NewChIPRelation(),
		NewChVTapPort(),
		NewChStringEnum(),
		NewChIntEnum(),
		NewChNodeType(),
		NewChAPPLabel(),
		// NewChTargetLabel(),
		// NewChPrometheusTargetLabelLayout(),
		NewChPrometheusLabelName(),
		NewChPrometheusMetricNames(),
		NewChPrometheusMetricAPPLabelLayout(),
		NewChTapType(c.resourceTypeToIconID),
		NewChVTap(c.resourceTypeToIconID),
		NewChLbListener(c.resourceTypeToIconID),

		NewChPolicy(),
		NewChNpbTunnel(),
		NewChAlarmPolicy(),
		NewChOSAppTag(),
		NewChOSAppTags(),
		NewChCustomBizService(c.resourceTypeToIconID),
		NewChCustomBizServiceFilter(),
	}

	if c.cfg.FPermit.Enabled {
		updaters = append(updaters, NewChUser())
	}
	for _, updater := range updaters {
		updater.SetConfig(c.cfg)
		updater.Refresh()
	}
}

type Updater interface {
	// 刷新ch资源入口
	// 基于资源基础数据，构建新的ch数据
	// 直接查询ch表，构建旧的ch数据
	// 遍历新的ch数据，若key不在旧的ch数据中，则新增；否则检查是否有更新，若有更新，则更新
	// 遍历旧的ch数据，若key不在新的ch数据中，则删除
	Refresh()
	SetConfig(cfg config.ControllerConfig)
}

type updaterDataGenerator[MT MySQLChModel, KT ChModelKey] interface {
	// 根据db中的基础资源数据，构建最新的ch资源数据
	generateNewData(*metadb.DB) (map[KT]MT, bool)
	// 构建ch资源的结构体key
	generateKey(MT) KT
	// 根据新旧数据对比，构建需要更新的ch资源数据
	generateUpdateInfo(MT, MT) (map[string]interface{}, bool)
}

type UpdaterComponent[MT MySQLChModel, KT ChModelKey] struct {
	cfg              config.ControllerConfig
	resourceTypeName string
	updaterDG        updaterDataGenerator[MT, KT]
	dbOperator       operator[MT, KT]
}

func newUpdaterComponent[MT MySQLChModel, KT ChModelKey](resourceTypeName string) UpdaterComponent[MT, KT] {
	u := UpdaterComponent[MT, KT]{
		resourceTypeName: resourceTypeName,
	}
	u.initDBOperator()
	return u
}

func (b *UpdaterComponent[MT, KT]) SetConfig(cfg config.ControllerConfig) {
	b.cfg = cfg
	b.dbOperator.setConfig(cfg)
}

func (b *UpdaterComponent[MT, KT]) initDBOperator() {
	b.dbOperator = newOperator[MT, KT](b.resourceTypeName)
}

func (b *UpdaterComponent[MT, KT]) Refresh() {
	// 遍历组织ID, 在每个组织的数据库中更新资源
	// Traverse the orgIDs, updating resources in each org's database
	orgIDs, err := metadb.GetORGIDs()
	if err != nil {
		log.Errorf("get org info fail : %s", err)
		return
	}

	for _, orgID := range orgIDs {
		db, err := metadb.GetDB(orgID)
		if err != nil {
			log.Error("get org dbinfo fail", logger.NewORGPrefix(orgID))
			continue
		}
		GetTeamInfo(db)
		newKeyToDBItem, newOK := b.updaterDG.generateNewData(db)
		oldKeyToDBItem, oldOK := b.generateOldData(db)
		keysToAdd := []KT{}
		itemsToAdd := []MT{}
		keysToDelete := []KT{}
		itemsToDelete := []MT{}
		if newOK && oldOK {
			for key, newDBItem := range newKeyToDBItem {
				oldDBItem, exists := oldKeyToDBItem[key]
				if !exists {
					keysToAdd = append(keysToAdd, key)
					itemsToAdd = append(itemsToAdd, newDBItem)
				} else {
					updateInfo, ok := b.updaterDG.generateUpdateInfo(oldDBItem, newDBItem)
					if ok {
						err := b.dbOperator.update(oldDBItem, updateInfo, key, db)
						if err != nil {
							log.Errorf("failed to update %s: %s", b.resourceTypeName, err, db.LogPrefixORGID)
						}
					}
				}
			}
			if len(itemsToAdd) > 0 {
				err := b.dbOperator.batchPage(keysToAdd, itemsToAdd, b.dbOperator.add, db) // 1是个占位符
				if err != nil {
					log.Errorf("failed to add %s: %s", b.resourceTypeName, err, db.LogPrefixORGID)
				}
			}

			for key, oldDBItem := range oldKeyToDBItem {
				_, exists := newKeyToDBItem[key]
				if !exists {
					keysToDelete = append(keysToDelete, key)
					itemsToDelete = append(itemsToDelete, oldDBItem)
				}
			}
			if len(itemsToDelete) > 0 {
				err := b.dbOperator.batchPage(keysToDelete, itemsToDelete, b.dbOperator.delete, db) // 1是个占位符
				if err != nil {
					log.Errorf("failed to delete %s: %s", b.resourceTypeName, err, db.LogPrefixORGID)
				}
			}
		}
	}
}

func (b *UpdaterComponent[MT, KT]) generateOldData(db *metadb.DB) (map[KT]MT, bool) {
	var items []MT
	var err error
	if b.resourceTypeName == RESOURCE_TYPE_CH_GPROCESS {
		items, err = query.FindInBatchesObj[MT](db.Unscoped())
	} else {
		err = db.Unscoped().Find(&items).Error
	}
	if err != nil {
		log.Errorf(dbQueryResourceFailed(b.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}
	idToItem := make(map[KT]MT)
	for _, item := range items {
		idToItem[b.updaterDG.generateKey(item)] = item
	}
	return idToItem, true
}

func (b *UpdaterComponent[MT, KT]) generateOneData(db *metadb.DB) (map[KT]MT, bool) {
	var items []MT
	err := db.Unscoped().First(&items).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(b.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}
	idToItem := make(map[KT]MT)
	for _, item := range items {
		idToItem[b.updaterDG.generateKey(item)] = item
	}
	return idToItem, true
}
