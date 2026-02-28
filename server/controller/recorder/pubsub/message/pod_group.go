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

type AddedPodGroups struct {
	MetadbItems[metadbmodel.PodGroup]
	addition[AddNoneAddition]
}

type DeletedPodGroups struct {
	Lcuuids
	MetadbItems[metadbmodel.PodGroup]
	addition[DeleteNoneAddition]
}

type UpdatedPodGroupFields struct {
	Key
	Name           fieldDetail[string]
	Label          fieldDetail[string]
	NetworkMode    fieldDetail[int]
	Type           fieldDetail[int]
	PodNum         fieldDetail[int]
	Metadata       fieldDetail[string]
	Spec           fieldDetail[string]
	AZLcuuid       fieldDetail[string]
	RegionLcuuid   fieldDetail[string]
	PodClusterID   fieldDetail[int]
	PodNamespaceID fieldDetail[int]
}

type UpdatedPodGroup struct {
	Fields[UpdatedPodGroupFields]
	MetadbData[metadbmodel.PodGroup]
}
