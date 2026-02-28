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

type AddedPodGroupPorts struct {
	MetadbItems[metadbmodel.PodGroupPort]
	addition[AddNoneAddition]
}

type DeletedPodGroupPorts struct {
	Lcuuids
	MetadbItems[metadbmodel.PodGroupPort]
	addition[DeleteNoneAddition]
}

type UpdatedPodGroupPortFields struct {
	Key
	Name fieldDetail[string]
}

type UpdatedPodGroupPort struct {
	Fields[UpdatedPodGroupPortFields]
	MetadbData[metadbmodel.PodGroupPort]
}
