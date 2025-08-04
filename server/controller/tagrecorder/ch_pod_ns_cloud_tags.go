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
	"encoding/json"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type ChPodNSCloudTags struct {
	SubscriberComponent[
		*message.PodNamespaceAdd,
		message.PodNamespaceAdd,
		*message.PodNamespaceUpdate,
		message.PodNamespaceUpdate,
		*message.PodNamespaceDelete,
		message.PodNamespaceDelete,
		metadbmodel.PodNamespace,
		metadbmodel.ChPodNSCloudTags,
		IDKey,
	]
}

func NewChPodNSCloudTags() *ChPodNSCloudTags {
	mng := &ChPodNSCloudTags{
		newSubscriberComponent[
			*message.PodNamespaceAdd,
			message.PodNamespaceAdd,
			*message.PodNamespaceUpdate,
			message.PodNamespaceUpdate,
			*message.PodNamespaceDelete,
			message.PodNamespaceDelete,
			metadbmodel.PodNamespace,
			metadbmodel.ChPodNSCloudTags,
			IDKey,
		](
			common.RESOURCE_TYPE_POD_NAMESPACE_EN, RESOURCE_TYPE_CH_POD_NS_CLOUD_TAGS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNSCloudTags) onResourceUpdated(md *message.Metadata, updateMessage *message.PodNamespaceUpdate) {
	db := md.GetDB()
	fieldsUpdate := updateMessage.GetFields().(*message.PodNamespaceFieldsUpdate)
	newSource := updateMessage.GetNewMetadbItem().(*metadbmodel.PodNamespace)
	sourceID := newSource.ID
	updateInfo := make(map[string]interface{})

	if !fieldsUpdate.LearnedCloudTags.IsDifferent() && !fieldsUpdate.CustomCloudTags.IsDifferent() {
		return
	}

	cloudTagMap := MergeCloudTags(newSource.LearnedCloudTags, newSource.CustomCloudTags)
	bytes, err := json.Marshal(cloudTagMap)
	if err != nil {
		log.Error(err, db.LogPrefixORGID)
		return
	}
	updateInfo["cloud_tags"] = string(bytes)

	targetKey := IDKey{ID: sourceID}
	if len(updateInfo) > 0 {
		var chItem metadbmodel.ChPodNSCloudTags
		db.Where("id = ?", sourceID).First(&chItem)
		if chItem.ID == 0 {
			c.SubscriberComponent.dbOperator.add(
				[]IDKey{targetKey},
				[]metadbmodel.ChPodNSCloudTags{{
					ChIDBase:    metadbmodel.ChIDBase{ID: sourceID},
					CloudTags:   updateInfo["cloud_tags"].(string),
					TeamID:      md.GetTeamID(),
					DomainID:    md.GetDomainID(),
					SubDomainID: md.GetSubDomainID(),
				}},
				db,
			)
		} else {
			c.SubscriberComponent.dbOperator.update(chItem, updateInfo, IDKey{ID: sourceID}, db)
		}
	}
	c.updateOrSync(db, targetKey, updateInfo)
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChPodNSCloudTags) sourceToTarget(md *message.Metadata, source *metadbmodel.PodNamespace) (keys []IDKey, targets []metadbmodel.ChPodNSCloudTags) {
	cloudTagMap := MergeCloudTags(source.LearnedCloudTags, source.CustomCloudTags)
	if len(cloudTagMap) == 0 {
		return
	}
	bytes, err := json.Marshal(cloudTagMap)
	if err != nil {
		log.Error(err, logger.NewORGPrefix(md.GetORGID()))
		return
	}
	return []IDKey{{ID: source.ID}}, []metadbmodel.ChPodNSCloudTags{{
		ChIDBase:    metadbmodel.ChIDBase{ID: source.ID},
		CloudTags:   string(bytes),
		TeamID:      md.GetTeamID(),
		DomainID:    md.GetDomainID(),
		SubDomainID: md.GetSubDomainID(),
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChPodNSCloudTags) softDeletedTargetsUpdated(targets []metadbmodel.ChPodNSCloudTags, db *metadb.DB) {

}
