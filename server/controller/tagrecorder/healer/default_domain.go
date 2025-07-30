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

package healer

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/common/metadata"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbModel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

func NewDefaultDomainHealers(db *metadb.DB) *Healers {
	platformMetadata, _ := metadata.NewPlatform(
		db.GetORGID(),
		metadata.MetadataDomain(
			metadbModel.Domain{Base: metadbModel.Base{Lcuuid: ctrlrcommon.DEFAULT_DOMAIN}, TeamID: ctrlrcommon.DEFAULT_TEAM_ID}))
	return NewHealers(platformMetadata)
}
