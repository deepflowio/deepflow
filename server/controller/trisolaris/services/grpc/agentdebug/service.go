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
	api "github.com/deepflowio/deepflow/message/agent"
	context "golang.org/x/net/context"
	"google.golang.org/grpc"

	grpcserver "github.com/deepflowio/deepflow/server/controller/grpc"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("trisolaris.agentdebug")

type service struct{}

func init() {
	grpcserver.Add(newService())
}

func newService() *service {
	return &service{}
}

func (s *service) Register(gs *grpc.Server) error {
	api.RegisterDebugServer(gs, s)
	return nil
}

func (s *service) DebugGPIDGlobalData(ctx context.Context, in *api.GPIDSyncRequest) (*api.GPIDGlobalData, error) {
	teamID := in.GetTeamId()
	orgID := trisolaris.GetOrgIDByTeamID(teamID)
	log.Infof("receive DebugGPIDGlobalLocalData about vtap(ctrl_ip: %s, ctrl_mac: %s, team_id: %s, org_id: %d)",
		in.GetCtrlIp(), in.GetCtrlMac(), teamID, orgID)

	processInfo := trisolaris.GetORGVTapInfo(orgID).GetAgentProcessInfo()
	if processInfo == nil {
		return &api.GPIDGlobalData{}, nil
	}
	entries := processInfo.GetGlobalEntries()
	return &api.GPIDGlobalData{
		Entries: entries,
	}, nil
}

func (s *service) DebugGPIDAgentData(ctx context.Context, in *api.GPIDSyncRequest) (*api.GPIDAgentData, error) {
	teamID := in.GetTeamId()
	orgID := trisolaris.GetOrgIDByTeamID(teamID)
	vtapCacheKey := in.GetCtrlIp() + "-" + in.GetCtrlMac()
	vtapCache := trisolaris.GetORGVTapInfo(orgID).GetVTapCache(vtapCacheKey)
	if vtapCache == nil {
		log.Infof("not found vtap(ctrl_ip: %s, ctrl_mac: %s, team_id: %s, org_id: %d) cache",
			in.GetCtrlIp(), in.GetCtrlMac(), teamID, orgID)
		return &api.GPIDAgentData{}, nil
	}
	log.Infof("receive DebugGPIDVTapLocalData about vtap(ctrl_ip: %s, ctrl_mac: %s, id: %d, team_id: %s, org_id: %d)",
		in.GetCtrlIp(), in.GetCtrlMac(), vtapCache.GetVTapID(), teamID, orgID)
	processInfo := trisolaris.GetORGVTapInfo(orgID).GetAgentProcessInfo()
	if processInfo == nil {
		return &api.GPIDAgentData{}, nil
	}
	req, updateTime := processInfo.GetAgentGPIDReq(uint32(vtapCache.GetVTapID()))
	return &api.GPIDAgentData{
		UpdateTime:  &updateTime,
		SyncRequest: req,
	}, nil
}

func (s *service) DebugRealGlobalData(ctx context.Context, in *api.GPIDSyncRequest) (*api.RealGlobalData, error) {
	teamID := in.GetTeamId()
	orgID := trisolaris.GetOrgIDByTeamID(teamID)
	processInfo := trisolaris.GetORGVTapInfo(orgID).GetAgentProcessInfo()
	if processInfo == nil {
		return &api.RealGlobalData{}, nil
	}
	return &api.RealGlobalData{
		Entries: processInfo.GetRealGlobalData(),
	}, nil
}

func (s *service) DebugRIPToVIP(ctx context.Context, in *api.GPIDSyncRequest) (*api.RVData, error) {
	teamID := in.GetTeamId()
	orgID := trisolaris.GetOrgIDByTeamID(teamID)
	processInfo := trisolaris.GetORGVTapInfo(orgID).GetAgentProcessInfo()
	if processInfo == nil {
		return &api.RVData{}, nil
	}
	return &api.RVData{
		Entries: processInfo.GetAgentRVData(),
	}, nil
}

func (s *service) DebugAgentCache(ctx context.Context, in *api.AgentCacheRequest) (*api.AgentCacheResponse, error) {
	teamID := in.GetTeamId()
	orgID := trisolaris.GetOrgIDByTeamID(teamID)
	vtapCacheKey := in.GetCtrlIp() + "-" + in.GetCtrlMac()
	vtapCache := trisolaris.GetORGVTapInfo(orgID).GetVTapCache(vtapCacheKey)
	if vtapCache == nil {
		log.Infof("not found vtap(ctrl_ip: %s, ctrl_mac: %s, team_id: %s, org_id: %d) cache",
			in.GetCtrlIp(), in.GetCtrlMac(), teamID, orgID)
		return &api.AgentCacheResponse{}, nil
	}
	agentCacheDebug := NewAgentCacheDebug(vtapCache)
	return &api.AgentCacheResponse{
		Content: agentCacheDebug.Marshal(),
	}, nil
}
