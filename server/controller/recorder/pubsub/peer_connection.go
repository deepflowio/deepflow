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

type PeerConnection struct {
	ResourcePubSubComponent[
		*message.AddedPeerConnections,
		message.AddedPeerConnections,
		message.AddNoneAddition,
		*message.UpdatedPeerConnection,
		message.UpdatedPeerConnection,
		*message.UpdatedPeerConnectionFields,
		message.UpdatedPeerConnectionFields,
		*message.DeletedPeerConnections,
		message.DeletedPeerConnections,
		message.DeleteNoneAddition]
}

func NewPeerConnection() *PeerConnection {
	return &PeerConnection{
		ResourcePubSubComponent[
			*message.AddedPeerConnections,
			message.AddedPeerConnections,
			message.AddNoneAddition,
			*message.UpdatedPeerConnection,
			message.UpdatedPeerConnection,
			*message.UpdatedPeerConnectionFields,
			message.UpdatedPeerConnectionFields,
			*message.DeletedPeerConnections,
			message.DeletedPeerConnections,
			message.DeleteNoneAddition,
		]{
			PubSubComponent: newPubSubComponent(PubSubTypePeerConnection),
			resourceType:    common.RESOURCE_TYPE_PEER_CONNECTION_EN,
		},
	}
}
