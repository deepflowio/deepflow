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

type AddedVMs struct {
	MetadbItems[metadbmodel.VM]
	addition[AddNoneAddition]
}

type DeletedVMs struct {
	Lcuuids
	MetadbItems[metadbmodel.VM]
	addition[DeleteNoneAddition]
}

type UpdatedVMFields struct {
	Key
	Name             fieldDetail[string]
	IP               fieldDetail[string]
	Label            fieldDetail[string]
	State            fieldDetail[int]
	HType            fieldDetail[int]
	LaunchServer     fieldDetail[string]
	LearnedCloudTags fieldDetail[map[string]string]
	CustomCloudTags  fieldDetail[map[string]string]
	HostID           fieldDetail[int]
	UID              fieldDetail[string]
	Hostname         fieldDetail[string]
	VPCID            fieldDetail[int]
	VPCLcuuid        fieldDetail[string]
	AZLcuuid         fieldDetail[string]
	RegionLcuuid     fieldDetail[string]
	NetworkID        fieldDetail[int]
	NetworkLcuuid    fieldDetail[string]
}

type UpdatedVM struct {
	Fields[UpdatedVMFields]
	MetadbData[metadbmodel.VM]
}
