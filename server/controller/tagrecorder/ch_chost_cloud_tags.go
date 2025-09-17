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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type ChChostCloudTags struct {
	SubscriberComponent[
		*message.AddedVMs,
		message.AddedVMs,
		*message.UpdatedVM,
		message.UpdatedVM,
		*message.DeletedVMs,
		message.DeletedVMs,
		mysqlmodel.VM,
		mysqlmodel.ChChostCloudTags,
		IDKey,
	]
}

func NewChChostCloudTags() *ChChostCloudTags {
	mng := &ChChostCloudTags{
		newSubscriberComponent[
			*message.AddedVMs,
			message.AddedVMs,
			*message.UpdatedVM,
			message.UpdatedVM,
			*message.DeletedVMs,
			message.DeletedVMs,
			mysqlmodel.VM,
			mysqlmodel.ChChostCloudTags,
			IDKey,
		](
			common.RESOURCE_TYPE_VM_EN, RESOURCE_TYPE_CH_CHOST_CLOUD_TAGS,
		),
	}
	mng.subscriberDG = mng
	return mng
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTags) onResourceUpdated(md *message.Metadata, updateMessage *message.UpdatedVM) {
}

// onResourceUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTags) sourceToTarget(md *message.Metadata, source *mysqlmodel.VM) (keys []IDKey, targets []mysqlmodel.ChChostCloudTags) {
	cloudTagMap := MergeCloudTags(source.LearnedCloudTags, source.CustomCloudTags)
	if len(cloudTagMap) == 0 {
		return
	}
	bytes, err := json.Marshal(cloudTagMap)
	if err != nil {
		log.Error(err, logger.NewORGPrefix(md.GetORGID()))
		return
	}
	return []IDKey{{ID: source.ID}}, []mysqlmodel.ChChostCloudTags{{
		ChIDBase:  mysqlmodel.ChIDBase{ID: source.ID},
		CloudTags: string(bytes),
		TeamID:    md.GetTeamID(),
		DomainID:  md.GetDomainID(),
	}}
}

// softDeletedTargetsUpdated implements SubscriberDataGenerator
func (c *ChChostCloudTags) softDeletedTargetsUpdated(targets []mysqlmodel.ChChostCloudTags, db *mysql.DB) {

}
