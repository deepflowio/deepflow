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

type PodNode struct {
	ResourcePubSubComponent[
		*message.AddedPodNodes,
		message.AddedPodNodes,
		message.AddNoneAddition,
		*message.UpdatedPodNode,
		message.UpdatedPodNode,
		*message.UpdatedPodNodeFields,
		message.UpdatedPodNodeFields,
		*message.DeletedPodNodes,
		message.DeletedPodNodes,
		message.DeleteNoneAddition]
}

func NewPodNode() *PodNode {
	return &PodNode{
		ResourcePubSubComponent[
			*message.AddedPodNodes,
			message.AddedPodNodes,
			message.AddNoneAddition,
			*message.UpdatedPodNode,
			message.UpdatedPodNode,
			*message.UpdatedPodNodeFields,
			message.UpdatedPodNodeFields,
			*message.DeletedPodNodes,
			message.DeletedPodNodes,
			message.DeleteNoneAddition,
		]{
			PubSubComponent: newPubSubComponent(PubSubTypePodNode),
			resourceType:    common.RESOURCE_TYPE_POD_NODE_EN,
		},
	}
}
