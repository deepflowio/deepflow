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

type AddedVInterfaces struct {
	MetadbItems[metadbmodel.VInterface]
	addition[AddNoneAddition]
}

type DeletedVInterfaces struct {
	Lcuuids
	MetadbItems[metadbmodel.VInterface]
	addition[DeleteNoneAddition]
}

type UpdatedVInterfaceFields struct {
	Key
	Name          fieldDetail[string]
	TapMac        fieldDetail[string]
	Type          fieldDetail[int]
	NetnsID       fieldDetail[uint32]
	VTapID        fieldDetail[uint32]
	NetworkID     fieldDetail[int]
	NetworkLcuuid fieldDetail[string]
	RegionLcuuid  fieldDetail[string]
}

type UpdatedVInterface struct {
	Fields[UpdatedVInterfaceFields]
	MetadbData[metadbmodel.VInterface]
}
