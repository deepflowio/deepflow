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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type ChPodNSCloudTag struct {
	SubscriberComponent[
		*message.AddedPodNamespaces,
		message.AddedPodNamespaces,
		*message.UpdatedPodNamespace,
		message.UpdatedPodNamespace,
		*message.DeletedPodNamespaces,
		message.DeletedPodNamespaces,
		mysqlmodel.PodNamespace,
		mysqlmodel.ChPodNSCloudTag,
		IDKeyKey,
	]
}

func NewChPodNSCloudTag() *ChPodNSCloudTag {
	mng := &ChPodNSCloudTag{
		newSubscriberComponent[
			*message.AddedPodNamespaces,
			message.AddedPodNamespaces,
			*message.UpdatedPodNamespace,
			message.UpdatedPodNamespace,
			*message.DeletedPodNamespaces,
			message.DeletedPodNamespaces,
			mysqlmodel.PodNamespace,
			mysqlmodel.ChPodNSCloudTag,
			IDKeyKey,
		](
			common.RESOURCE_TYPE_POD_NAMESPACE_EN, RESOURCE_TYPE_CH_POD_NS_CLOUD_TAG,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNSCloudTag) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedPodNamespace) {
	db := md.GetDB()
	fieldsUpdate := updateMessage.GetFields().(*message.UpdatedPodNamespaceFields)
	newSource := updateMessage.GetNewMySQL().(*mysqlmodel.PodNamespace)
	sourceID := newSource.ID
	new := map[string]string{}
	old := map[string]string{}
	updateInfo := make(map[string]interface{})
	keysToAdd := make([]IDKeyKey, 0)
	targetsToAdd := make([]mysqlmodel.ChPodNSCloudTag, 0)
	keysToDelete := make([]IDKeyKey, 0)
	targetsToDelete := make([]mysqlmodel.ChPodNSCloudTag, 0)

	if !fieldsUpdate.LearnedCloudTags.IsDifferent() && !fieldsUpdate.CustomCloudTags.IsDifferent() {
		return
	}

	if fieldsUpdate.LearnedCloudTags.IsDifferent() {
		for k, v := range fieldsUpdate.LearnedCloudTags.GetNew() {
			new[k] = v
		}
		for k, v := range fieldsUpdate.LearnedCloudTags.GetOld() {
			old[k] = v
		}
	} else {
		for k, v := range newSource.LearnedCloudTags {
			new[k] = v
			old[k] = v
		}
	}
	// custom cloud tag has a higher priority
	if fieldsUpdate.CustomCloudTags.IsDifferent() {
		for k, v := range fieldsUpdate.CustomCloudTags.GetNew() {
			new[k] = v
		}
		for k, v := range fieldsUpdate.CustomCloudTags.GetOld() {
			old[k] = v
		}
	} else {
		for k, v := range newSource.CustomCloudTags {
			new[k] = v
			old[k] = v
		}
	}

	for k, v := range new {
		targetKey := NewIDKeyKey(sourceID, k)
		oldV, ok := old[k]
		if !ok {
			keysToAdd = append(keysToAdd, targetKey)
			targetsToAdd = append(targetsToAdd, mysqlmodel.ChPodNSCloudTag{
				ChIDBase:    mysqlmodel.ChIDBase{ID: sourceID},
				Key:         k,
				Value:       v,
				TeamID:      md.GetTeamID(),
				DomainID:    md.GetDomainID(),
				SubDomainID: md.GetSubDomainID(),
			})
			continue
		}

		if oldV != v {
			var chItem mysqlmodel.ChPodNSCloudTag
			db.Where("id = ? and `key` = ?", sourceID, k).First(&chItem)
			if chItem.ID == 0 {
				keysToAdd = append(keysToAdd, targetKey)
				targetsToAdd = append(targetsToAdd, mysqlmodel.ChPodNSCloudTag{
					ChIDBase:    mysqlmodel.ChIDBase{ID: sourceID},
					Key:         k,
					Value:       v,
					TeamID:      md.GetTeamID(),
					DomainID:    md.GetDomainID(),
					SubDomainID: md.GetSubDomainID(),
				})
				continue
			}
			updateInfo["value"] = v
		}
		c.updateOrSync(db, targetKey, updateInfo)
	}
	for k := range old {
		if _, ok := new[k]; !ok {
			keysToDelete = append(keysToDelete, NewIDKeyKey(sourceID, k))
			targetsToDelete = append(targetsToDelete, mysqlmodel.ChPodNSCloudTag{
				ChIDBase: mysqlmodel.ChIDBase{ID: sourceID},
				Key:      k,
			})
		}
	}

	if len(keysToAdd) > 0 {
		c.SubscriberComponent.dbOperator.add(keysToAdd, targetsToAdd, db)
	}
	if len(keysToDelete) > 0 {
		c.SubscriberComponent.dbOperator.delete(keysToDelete, targetsToDelete, db)
	}
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNSCloudTag) sourceToTarget(md *message.Metadata, source *mysqlmodel.PodNamespace) (keys []IDKeyKey, targets []mysqlmodel.ChPodNSCloudTag) {
	cloudTagMap := MergeCloudTags(source.LearnedCloudTags, source.CustomCloudTags)
	for k, v := range cloudTagMap {
		keys = append(keys, NewIDKeyKey(source.ID, k))
		targets = append(targets, mysqlmodel.ChPodNSCloudTag{
			ChIDBase:    mysqlmodel.ChIDBase{ID: source.ID},
			Key:         k,
			Value:       v,
			TeamID:      md.GetTeamID(),
			DomainID:    md.GetDomainID(),
			SubDomainID: md.GetSubDomainID(),
		})
	}
	return
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodNSCloudTag) softDeletedTargetsUpdated(targets []mysqlmodel.ChPodNSCloudTag, db *mysql.DB) {

}
