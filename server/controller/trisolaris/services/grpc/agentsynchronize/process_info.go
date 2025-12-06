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
	context "golang.org/x/net/context"

	api "github.com/deepflowio/deepflow/message/agent"
	"github.com/deepflowio/deepflow/server/controller/grpc/statsd"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/gogo/protobuf/proto"
)

var EmptyGPIDResponse = &api.GPIDSyncResponse{}

type ProcessInfoEvent struct{}

func NewprocessInfoEvent() *ProcessInfoEvent {
	return &ProcessInfoEvent{}
}

func (e *ProcessInfoEvent) GPIDSync(ctx context.Context, in *api.GPIDSyncRequest) (*api.GPIDSyncResponse, error) {
	orgID := trisolaris.GetOrgIDByTeamID(in.GetTeamId())
	gVTapInfo := trisolaris.GetORGVTapInfo(orgID)
	if gVTapInfo == nil {
		return EmptyGPIDResponse, nil
	}
	processInfo := gVTapInfo.GetAgentProcessInfo()
	vtapCacheKey := in.GetCtrlIp() + "-" + in.GetCtrlMac()
	vtapCache := gVTapInfo.GetVTapCache(vtapCacheKey)
	if vtapCache == nil {
		log.Infof("receive invalid gpid sync data from vtap(ctrl_ip: %s, ctrl_mac: %s team_id: %s), because vtap is not cache",
			in.GetCtrlIp(), in.GetCtrlMac(), in.GetTeamId(), logger.NewORGPrefix(orgID))
		return EmptyGPIDResponse, nil
	}
	if in.GetAgentId() == 0 {
		response := processInfo.GetGPIDResponseByVtapID(vtapCache.GetVTapID())
		syncBytesSize := uint64(proto.Size(response))
		currentBufferSize := vtapCache.GetGRPCBufferFromLastGPIDSync(syncBytesSize)
		if exceedsGRPCBuffer(currentBufferSize, syncBytesSize) {
			log.Warningf("agent (%s) need sync gpid size: %d more than max buffer size: %d, stop sync", vtapCacheKey, syncBytesSize, currentBufferSize, logger.NewORGPrefix(orgID))
			return EmptyGPIDResponse, nil
		}
		log.Infof("receive debug gpid sync data by vtap(ctrl_ip: %s, ctrl_mac: %s vtap_id: %d  team_id: %s)",
			in.GetCtrlIp(), in.GetCtrlMac(), vtapCache.GetVTapID(), in.GetTeamId(), logger.NewORGPrefix(orgID))
		return response, nil
	}

	statsd.AddGPIDReceiveCounter(uint64(len(in.GetEntries())))

	log.Infof("receive gpid sync data from vtap(ctrl_ip: %s, ctrl_mac: %s, vtap_id: %d, team_id: %s) data_len: %d",
		in.GetCtrlIp(), in.GetCtrlMac(), in.GetAgentId(), in.GetTeamId(), len(in.GetEntries()), logger.NewORGPrefix(orgID))
	processInfo.UpdateAgentGPIDReq(in)
	resp := processInfo.GetGPIDResponseByReq(in)
	syncBytesSize := uint64(proto.Size(resp))
	currentBufferSize := vtapCache.GetGRPCBufferFromLastGPIDSync(syncBytesSize)
	if exceedsGRPCBuffer(currentBufferSize, syncBytesSize) {
		log.Warningf("agent (%s) need sync gpid size: %d more than max buffer size: %d, stop sync", vtapCacheKey, syncBytesSize, currentBufferSize, logger.NewORGPrefix(orgID))
		return EmptyGPIDResponse, nil
	}
	log.Infof("send gpid response data(len=%d) to vtap(ctrl_ip: %s, ctrl_mac: %s, vtap_id: %d, team_id: %s)",
		len(resp.GetEntries()), in.GetCtrlIp(), in.GetCtrlMac(), in.GetAgentId(), in.GetTeamId(), logger.NewORGPrefix(orgID))
	statsd.AddGPIDSendCounter(uint64(len(resp.GetEntries())))
	return resp, nil
}

func (e *ProcessInfoEvent) ShareGPIDLocalData(ctx context.Context, in *api.ShareGPIDSyncRequests) (*api.ShareGPIDSyncRequests, error) {
	log.Infof("receive gpid sync data from server(%s)", in.GetServerIp(), logger.NewORGPrefix(int(in.GetOrgId())))
	processInfo := trisolaris.GetORGVTapInfo(int(in.GetOrgId())).GetAgentProcessInfo()
	if processInfo == nil {
		return &api.ShareGPIDSyncRequests{}, nil
	}
	processInfo.UpdateGPIDReqFromShare(in)
	shareData := processInfo.GetGPIDShareReqs()
	if shareData == nil {
		shareData = &api.ShareGPIDSyncRequests{}
	}
	return shareData, nil
}
