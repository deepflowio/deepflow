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

package synchronize

import (
	context "golang.org/x/net/context"

	api "github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/grpc/statsd"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
)

var EmptyGPIDResponse = &api.GPIDSyncResponse{}

type ProcessInfoEvent struct{}

func NewprocessInfoEvent() *ProcessInfoEvent {
	return &ProcessInfoEvent{}
}

func (e *ProcessInfoEvent) GPIDSync(ctx context.Context, in *api.GPIDSyncRequest) (*api.GPIDSyncResponse, error) {
	orgID := trisolaris.GetOrgIDByTeamID(in.GetTeamId())
	gVTapInfo := trisolaris.GetGVTapInfo(orgID)
	if gVTapInfo == nil {
		return EmptyGPIDResponse, nil
	}
	processInfo := gVTapInfo.GetProcessInfo()
	if in.GetVtapId() == 0 {
		vtapCacheKey := in.GetCtrlIp() + "-" + in.GetCtrlMac()
		vtapCache := gVTapInfo.GetVTapCache(vtapCacheKey)
		if vtapCache != nil {
			log.Infof("receive debug gpid sync data by vtap(ctrl_ip: %s, ctrl_mac: %s vtap_id: %d  team_id: %s org_id: %d)",
				in.GetCtrlIp(), in.GetCtrlMac(), vtapCache.GetVTapID(), in.GetTeamId(), orgID)
			return processInfo.GetGPIDResponseByVtapID(vtapCache.GetVTapID()), nil
		}
		log.Infof("receive invalid gpid sync data from vtap(ctrl_ip: %s, ctrl_mac: %s team_id: %s org_id: %d), because vtap_id=%d(vtap is not registered)",
			in.GetCtrlIp(), in.GetCtrlMac(), in.GetTeamId(), orgID, in.GetVtapId())

		return EmptyGPIDResponse, nil
	}

	statsd.AddGPIDReceiveCounter(uint64(len(in.GetEntries())))

	log.Infof("receive gpid sync data from vtap(ctrl_ip: %s, ctrl_mac: %s, vtap_id: %d, team_id: %s, org_id: %d) data_len: %d",
		in.GetCtrlIp(), in.GetCtrlMac(), in.GetVtapId(), in.GetTeamId(), orgID, len(in.GetEntries()))
	processInfo.UpdateAgentGPIDReq(in)
	resp := processInfo.GetGPIDResponseByReq(in)
	log.Infof("send gpid response data(len=%d) to vtap(ctrl_ip: %s, ctrl_mac: %s, vtap_id: %d, team_id: %s, org_id: %d)",
		len(resp.GetEntries()), in.GetCtrlIp(), in.GetCtrlMac(), in.GetVtapId(), in.GetTeamId(), orgID)
	statsd.AddGPIDSendCounter(uint64(len(resp.GetEntries())))
	return resp, nil
}

func (e *ProcessInfoEvent) ShareGPIDLocalData(ctx context.Context, in *api.ShareGPIDSyncRequests) (*api.ShareGPIDSyncRequests, error) {
	log.Infof("receive gpid sync data from server(%s) ORGID(%d)", in.GetServerIp(), in.GetOrgId())
	processInfo := trisolaris.GetGVTapInfo(int(in.GetOrgId())).GetProcessInfo()
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
