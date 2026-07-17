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
	"fmt"

	context "golang.org/x/net/context"

	api "github.com/deepflowio/deepflow/message/agent"
	"github.com/deepflowio/deepflow/server/controller/grpc/statsd"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/common"
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

func (e *ProcessInfoEvent) ProcessGPIDSync(ctx context.Context, in *api.ProcessGPIDSyncRequest) (*api.ProcessGPIDSyncResponse, error) {
	vtapCacheKey := fmt.Sprintf("%s-%s", in.AgentId.GetIp(), in.AgentId.GetMac())
	teamIDStr := in.AgentId.GetTeamId()
	orgID := trisolaris.GetOrgIDByTeamID(teamIDStr)
	if orgID == 0 {
		log.Warningf("receive process gpid sync from vtap (%s), invalid team short id:%s", in.AgentId.GetIp(), teamIDStr)
		return &api.ProcessGPIDSyncResponse{}, nil
	}

	gVTapInfo := trisolaris.GetORGVTapInfo(orgID)
	if gVTapInfo == nil {
		log.Warningf("receive process gpid sync from vtap (%s) team (%s), not found org (%d) vtap info", in.AgentId.GetIp(), teamIDStr, orgID)
		return &api.ProcessGPIDSyncResponse{}, nil
	}

	vtapCache := gVTapInfo.GetVTapCache(vtapCacheKey)
	if vtapCache == nil {
		log.Infof("receive process gpid sync from vtap (%s) team (%s), vtap is not cache", vtapCacheKey, teamIDStr, logger.NewORGPrefix(orgID))
		return &api.ProcessGPIDSyncResponse{}, nil
	}

	metadata := trisolaris.GetMetaData(orgID)
	if metadata == nil {
		log.Warningf("receive process gpid sync from vtap (%s) team (%s), not found org (%d) metadata", in.AgentId.GetIp(), teamIDStr, orgID)
		return &api.ProcessGPIDSyncResponse{}, nil
	}

	agentMetaData := metadata.GetAgentMetaData()
	if agentMetaData == nil {
		log.Warningf("receive process gpid sync from vtap (%s) team (%s), not found org (%d) agent metadata", in.AgentId.GetIp(), teamIDStr, orgID)
		return &api.ProcessGPIDSyncResponse{}, nil
	}

	agentVersion := in.GetProcessGpidVersion()
	version, processGPIDBytes := agentMetaData.GetCompressProcessGPID(agentVersion)
	log.Infof("receive process gpid sync from vtap (%s) team (%s) version (%d=>%d)", vtapCacheKey, teamIDStr, agentVersion, version, logger.NewORGPrefix(orgID))
	result := &api.ProcessGPIDSyncResponse{
		GprocessInfos:      processGPIDBytes,
		ProcessGpidVersion: proto.Uint64(version),
		CompressAlgorithm:  &common.PROCESS_GPID_COMPRESS_ALGO_ZSTD,
	}
	syncBytesSize := uint64(proto.Size(result))
	currentBufferSize := vtapCache.GetGRPCBufferFromLastProcessGPIDSync(syncBytesSize)
	if exceedsGRPCBuffer(currentBufferSize, syncBytesSize) {
		log.Warningf("agent (%s) need sync process gpid size: %d more than max buffer size: %d, stop sync", vtapCacheKey, syncBytesSize, currentBufferSize, logger.NewORGPrefix(orgID))
		return &api.ProcessGPIDSyncResponse{}, nil
	}
	return result, nil
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
