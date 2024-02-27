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

package pubsub

import (
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type Region struct {
	ResourcePubSubComponent[
		*message.RegionAdd,
		message.RegionAdd,
		*message.RegionUpdate,
		message.RegionUpdate,
		*message.RegionFieldsUpdate,
		message.RegionFieldsUpdate,
		*message.RegionDelete,
		message.RegionDelete]
}

func NewRegion() *Region {
	return &Region{
		ResourcePubSubComponent[
			*message.RegionAdd,
			message.RegionAdd,
			*message.RegionUpdate,
			message.RegionUpdate,
			*message.RegionFieldsUpdate,
			message.RegionFieldsUpdate,
			*message.RegionDelete,
			message.RegionDelete,
		]{
			PubSubComponent: newPubSubComponent(PubSubTypeRegion),
			resourceType:    common.RESOURCE_TYPE_REGION_EN,
		},
	}
}
