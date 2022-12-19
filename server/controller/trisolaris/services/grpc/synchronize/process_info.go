/*
 * Copyright (c) 2022 Yunshan Networks
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

	api "github.com/deepflowys/deepflow/message/trident"
	"github.com/deepflowys/deepflow/server/controller/trisolaris"
)

var EmptyGPIDResponse = &api.GPIDSyncResponse{}

type ProcessInfoEvent struct{}

func NewprocessInfoEvent() *ProcessInfoEvent {
	return &ProcessInfoEvent{}
}

func getReq(vtapID uint32) *api.GPIDSyncResponse {
	req := trisolaris.GetGVTapInfo().GetProcessInfo().GetGPIDResponse(vtapID)
	if req == nil {
		req = EmptyGPIDResponse
	}

	return req
}

func (e *ProcessInfoEvent) GPIDSync(ctx context.Context, in *api.GPIDSyncRequest) (*api.GPIDSyncResponse, error) {
	processInfo := trisolaris.GetGVTapInfo().GetProcessInfo()
	if in.GetVtapId() == 0 {
		gVTapInfo := trisolaris.GetGVTapInfo()
		vtapCacheKey := in.GetCtrlIp() + "-" + in.GetCtrlMac()
		vtapCache := gVTapInfo.GetVTapCache(vtapCacheKey)
		if vtapCache != nil {
			log.Infof("receive debug gpid sync data by vtap(ctrl_ip: %s, ctrl_mac: %s vtap_id: %d)",
				in.GetCtrlIp(), in.GetCtrlMac(), vtapCache.GetVTapID())
			return getReq(uint32(vtapCache.GetVTapID())), nil
		}
		log.Infof("receive invalid gpid sync data from vtap(ctrl_ip: %s, ctrl_mac: %s), because vtap_id=%d(vtap is not registered)",
			in.GetCtrlIp(), in.GetCtrlMac(), in.GetVtapId())

		return EmptyGPIDResponse, nil
	}

	if len(in.GetLocalEntries()) != 0 || len(in.GetPeerEntries()) != 0 {
		if in.GetCtrlIp() != "" && in.GetCtrlMac() != "" {
			log.Infof("receive gpid sync data from vtap(ctrl_ip: %s, ctrl_mac: %s, vtap_id:%d)",
				in.GetCtrlIp(), in.GetCtrlMac(), in.GetVtapId())
			processInfo.UpdateVTapGPIDReq(in)
			return getReq(in.GetVtapId()), nil
		} else {
			log.Infof("receive gpid sync data from server(server_ip: %s, ctrl_mac: %s, vtap_id:%d)",
				in.GetCtrlIp(), in.GetCtrlMac(), in.GetVtapId())
			processInfo.UpdateGPIDReqFromShare(in)
			return EmptyGPIDResponse, nil
		}
	}
	log.Infof("receive gpid debug request by vtap(ctrl_ip: %s, ctrl_mac: %s, vtap_id:%d)",
		in.GetCtrlIp(), in.GetCtrlMac(), in.GetVtapId())

	return getReq(in.GetVtapId()), nil
}
