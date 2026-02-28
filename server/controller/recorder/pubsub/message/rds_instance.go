/**
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

package message

import (
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type AddedRDSInstances struct {
	MetadbItems[metadbmodel.RDSInstance]
	addition[AddNoneAddition]
}

type DeletedRDSInstances struct {
	Lcuuids
	MetadbItems[metadbmodel.RDSInstance]
	addition[DeleteNoneAddition]
}

type UpdatedRDSInstanceFields struct {
	Key
	Name         fieldDetail[string]
	UID          fieldDetail[string]
	State        fieldDetail[int]
	Series       fieldDetail[int]
	Model        fieldDetail[int]
	AZLcuuid     fieldDetail[string]
	RegionLcuuid fieldDetail[string]
}

type UpdatedRDSInstance struct {
	Fields[UpdatedRDSInstanceFields]
	MetadbData[metadbmodel.RDSInstance]
}
