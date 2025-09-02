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

package agentsynchronize

import (
	"math"

	context "golang.org/x/net/context"
	"google.golang.org/grpc/peer"

	. "github.com/deepflowio/deepflow/server/controller/common"
	common "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
)

func getRemote(ctx context.Context) string {
	remote := ""
	peerIP, _ := peer.FromContext(ctx)
	remote = peerIP.Addr.String()
	return remote
}

func isPodVTap(vtapType int) bool {
	switch vtapType {
	case VTAP_TYPE_POD_VM, VTAP_TYPE_POD_HOST, VTAP_TYPE_K8S_SIDECAR:
		return true
	default:
		return false
	}
}

func checkGRPCBufferSize(currentSize, sendBytes uint64) (uint64, bool) {
	// the minimum size of the agent grpc buffer is 1MB
	if currentSize < common.MEGA_BYTE {
		return 0, false
	}

	requiredSize := uint64(math.Ceil(float64(sendBytes+common.BUFFER_SIZE_EXTRA)/common.MEGA_BYTE)) * common.MEGA_BYTE

	// 检查是否需要增大缓冲区
	if requiredSize > currentSize {
		return requiredSize, true
	}

	// 检查是否可以减小缓冲区（小于当前大小的一半）
	if requiredSize < currentSize/2 {
		return requiredSize, true
	}

	return currentSize, false
}
