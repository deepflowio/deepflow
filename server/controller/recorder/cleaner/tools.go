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

package cleaner

import (
	"fmt"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"

	ctrlCommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	msgConstraint "github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/constraint"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

func WhereFindPtr[T any](db *metadb.DB, query interface{}, args ...interface{}) ([]*T, error) {
	var result []*T
	err := db.Where(query, args...).Find(&result).Error
	return result, err
}

func formatLogDeleteABecauseBHasGone[MT metadbmodel.AssetResourceConstraint](a, b string, items []*MT) string {
	var str string
	for _, item := range items {
		str += fmt.Sprintf("%+v ", item)
	}
	return fmt.Sprintf("%s: %+v because %s has gone", common.LogDelete(a), str, b)
}

func getIDs[MT metadbmodel.AssetResourceConstraint](db *metadb.DB, domainLcuuid string) (ids []int) {
	var dbItems []*MT
	db.Where(map[string]interface{}{"domain": domainLcuuid}).Select("id").Find(&dbItems)
	for _, item := range dbItems {
		ids = append(ids, (*item).GetID())
	}
	return
}

func pageDeleteExpiredAndPublish[MDPT msgConstraint.DeletePtr[MDT], MDT msgConstraint.Delete, MT constraint.MetadbSoftDeleteModel](
	db *metadb.DB, expiredAt time.Time, resourceType string, toolData *toolData, size int) {
	var items []*MT
	err := db.Unscoped().Where("deleted_at < ?", expiredAt).Find(&items).Error
	if err != nil {
		log.Errorf("metadb delete %s resource failed: %s", resourceType, err.Error(), db.LogPrefixORGID)
		return
	}
	if len(items) == 0 {
		return
	}

	log.Infof("clean %s started: %d", resourceType, len(items), db.LogPrefixORGID)
	total := len(items)
	for i := 0; i < total; i += size {
		end := i + size
		if end > total {
			end = total
		}
		if err := db.Unscoped().Delete(items[i:end]).Error; err != nil {
			log.Errorf("metadb delete %s resource failed: %s", resourceType, err.Error(), db.LogPrefixORGID)
		} else {
			publishTagrecorder[MDPT, MDT, MT](db, items, resourceType, toolData)
		}
	}

	log.Infof("clean %s completed: %d", resourceType, len(items), db.LogPrefixORGID)
}

func publishTagrecorder[MDPT msgConstraint.DeletePtr[MDT], MDT msgConstraint.Delete, MT constraint.MetadbSoftDeleteModel](db *metadb.DB, dbItems []*MT, resourceType string, toolData *toolData) {
	msgMetadataToDBItems := make(map[*message.Metadata][]*MT)
	for _, item := range dbItems {
		var msgMetadata *message.Metadata
		if (*item).GetSubDomainLcuuid() != "" {
			msgMetadata = toolData.subDomainLcuuidToMsgMetadata[(*item).GetSubDomainLcuuid()]
		} else {
			msgMetadata = toolData.domainLcuuidToMsgMetadata[(*item).GetDomainLcuuid()]
		}
		if msgMetadata == nil {
			log.Errorf("failed to get metadata for %s: %#v", resourceType, item, db.LogPrefixORGID)
			continue
		}
		msgMetadataToDBItems[msgMetadata] = append(msgMetadataToDBItems[msgMetadata], item)
	}
	if len(msgMetadataToDBItems) == 0 {
		return
	}

	for _, sub := range tagrecorder.GetSubscriberManager().GetSubscribers(resourceType) { // TODO use pubsub
		for msgMetadata, dbItems := range msgMetadataToDBItems {
			msgData := MDPT(new(MDT))
			msgData.SetMetadbItems(dbItems)
			if resourceType == ctrlCommon.RESOURCE_TYPE_PROCESS_EN {
				msgData.SetAddition(getProcessMessageDeleteAddition(db, dbItems, resourceType, toolData)) // TODO optimize
				log.Infof("process delete addition: %s", msgData.GetAddition(), db.LogPrefixORGID)
			}
			sub.OnResourceBatchDeleted(msgMetadata, msgData)
		}
	}
}

func getProcessMessageDeleteAddition(db *metadb.DB, dbItems interface{}, resourceType string, toolData *toolData) *message.ProcessDeleteAddition {
	addition := &message.ProcessDeleteAddition{}
	var allProcesses []*metadbmodel.Process
	if err := db.Unscoped().Find(&allProcesses).Error; err != nil {
		log.Errorf("failed to get all processes: %s", err.Error(), db.LogPrefixORGID)
		return addition
	}
	gidToCount := make(map[uint32]int)
	for _, item := range allProcesses {
		gidToCount[item.GID]++
	}
	deletedGIDs := mapset.NewSet[uint32]()
	for _, item := range dbItems.([]*metadbmodel.Process) {
		if _, ok := gidToCount[item.GID]; !ok {
			deletedGIDs.Add(item.GID)
		}
	}
	return &message.ProcessDeleteAddition{DeletedGIDs: deletedGIDs.ToSlice()}
}

type toolData struct {
	mux sync.Mutex

	domainLcuuidToMsgMetadata    map[string]*message.Metadata
	subDomainLcuuidToMsgMetadata map[string]*message.Metadata
}

func newToolData() *toolData {
	return &toolData{
		domainLcuuidToMsgMetadata:    make(map[string]*message.Metadata),
		subDomainLcuuidToMsgMetadata: make(map[string]*message.Metadata),
	}
}

func (t *toolData) clean() {
	t.domainLcuuidToMsgMetadata = make(map[string]*message.Metadata)
	t.subDomainLcuuidToMsgMetadata = make(map[string]*message.Metadata)
}

func (t *toolData) load(db *metadb.DB) error {
	t.mux.Lock()
	defer t.mux.Unlock()

	t.clean()

	var domains []*metadbmodel.Domain
	if err := db.Find(&domains).Error; err != nil {
		log.Errorf("failed to get domain: %s", err.Error(), db.LogPrefixORGID)
		return err
	}
	lcuuidToDomain := make(map[string]*metadbmodel.Domain)
	for _, domain := range domains {
		lcuuidToDomain[domain.Lcuuid] = domain
		t.domainLcuuidToMsgMetadata[domain.Lcuuid] = message.NewMetadata(
			message.MetadataDB(db), message.MetadataDomain(*domain))
	}
	var subDomains []*metadbmodel.SubDomain
	if err := db.Find(&subDomains).Error; err != nil {
		log.Errorf("failed to get sub_domain: %s", err.Error(), db.LogPrefixORGID)
		return err
	}
	for _, subDomain := range subDomains {
		t.subDomainLcuuidToMsgMetadata[subDomain.Lcuuid] = message.NewMetadata(
			message.MetadataDB(db), message.MetadataSubDomain(*subDomain), message.MetadataDomain(*lcuuidToDomain[subDomain.Domain]),
		)
	}
	return nil
}
