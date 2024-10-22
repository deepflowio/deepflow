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

package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/deepflowio/deepflow/message/agent"
	mysqlcommon "github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"google.golang.org/grpc/peer"
)

func isAgentInterestedHost(aType agent.AgentType) bool {
	types := []agent.AgentType{agent.AgentType_TT_PROCESS, agent.AgentType_TT_HOST_POD, agent.AgentType_TT_VM_POD, agent.AgentType_TT_PHYSICAL_MACHINE, agent.AgentType_TT_PUBLIC_CLOUD, agent.AgentType_TT_K8S_SIDECAR}
	for _, t := range types {
		if t == aType {
			return true
		}
	}
	return false
}

func (g *SynchronizerServer) AgentGenesisSync(ctx context.Context, request *agent.GenesisSyncRequest) (*agent.GenesisSyncResponse, error) {
	k8sClusterID := request.GetKubernetesClusterId()
	remote := ""
	peerIP, _ := peer.FromContext(ctx)
	sourceIP := request.GetSourceIp()
	if sourceIP != "" {
		remote = sourceIP
	} else {
		remote = peerIP.Addr.String()
	}
	version := request.GetVersion()
	if version == 0 {
		log.Warningf("genesis sync ignore message with version 0 from %s", remote)
		return &agent.GenesisSyncResponse{}, nil
	}

	vtapID := request.GetAgentId()
	tType := request.GetAgentType()
	if !isAgentInterestedHost(tType) {
		log.Debugf("genesis sync ignore message from %s agent %s vtap_id %v", tType, remote, vtapID)
		return &agent.GenesisSyncResponse{Version: &version}, nil
	}

	var orgID, teamID int
	teamShortLcuuid := request.GetTeamId()
	if teamShortLcuuid == "" {
		orgID = mysqlcommon.DEFAULT_ORG_ID
		teamID = mysqlcommon.DEFAULT_TEAM_ID
	} else {
		t, ok := g.teamShortLcuuidToInfo.Load(teamShortLcuuid)
		if ok {
			orgID = t.(common.TeamInfo).OrgID
			teamID = t.(common.TeamInfo).TeamId
		} else {
			teamShortLcuuidToInfo, err := common.GetTeamShortLcuuidToInfo()
			if err != nil {
				log.Errorf("genesis sync from %s team_id %s vtap get team info failed: %s", remote, teamShortLcuuid, err.Error())
				return &agent.GenesisSyncResponse{Version: &version}, nil
			}
			teamInfo, ok := teamShortLcuuidToInfo[teamShortLcuuid]
			if !ok {
				log.Errorf("genesis sync from %s team_id %s not found team info", remote, teamShortLcuuid)
				return &agent.GenesisSyncResponse{Version: &version}, nil
			}
			orgID = teamInfo.OrgID
			teamID = teamInfo.TeamId
			for k, v := range teamShortLcuuidToInfo {
				g.teamShortLcuuidToInfo.Store(k, v)
			}
		}
	}
	vtap := fmt.Sprintf("%d-%d", orgID, vtapID)

	var localVersion uint64 = 0
	if vtapID == 0 {
		log.Infof("genesis sync received message with vtap_id 0 from %s", remote, logger.NewORGPrefix(orgID))
	} else {
		now := time.Now()
		if lTime, ok := g.vtapToLastSeen.Load(vtap); ok {
			lastTime := lTime.(time.Time)
			var agingTime float64 = 0
			if g.cfg.AgingTime < g.cfg.VinterfaceAgingTime {
				agingTime = g.cfg.AgingTime
			} else {
				agingTime = g.cfg.VinterfaceAgingTime
			}
			if now.Sub(lastTime).Seconds() >= agingTime {
				g.vtapToVersion.Store(vtap, uint64(0))
			}
		}
		g.vtapToLastSeen.Store(vtap, now)
		lVersion, ok := g.vtapToVersion.Load(vtap)
		if ok {
			localVersion = lVersion.(uint64)
		}
	}

	platformData := request.GetPlatformData()
	if version == localVersion || platformData == nil {
		log.Debugf("genesis sync renew version %v from ip %s vtap_id %v", version, remote, vtapID, logger.NewORGPrefix(orgID))
		g.genesisSyncQueue.Put(
			common.VIFRPCMessage{
				Peer:         remote,
				VtapID:       vtapID,
				ORGID:        orgID,
				TeamID:       uint32(teamID),
				MessageType:  common.TYPE_RENEW,
				AgentMessage: request,
			},
		)
		return &agent.GenesisSyncResponse{Version: &localVersion}, nil
	}

	log.Infof("genesis sync received version %v -> %v from ip %s vtap_id %v", localVersion, version, remote, vtapID, logger.NewORGPrefix(orgID))
	g.genesisSyncQueue.Put(
		common.VIFRPCMessage{
			Peer:         remote,
			VtapID:       vtapID,
			ORGID:        orgID,
			TeamID:       uint32(teamID),
			K8SClusterID: k8sClusterID,
			MessageType:  common.TYPE_UPDATE,
			AgentMessage: request,
		},
	)

	if vtapID != 0 {
		var stats TridentStats
		if s, ok := g.tridentStatsMap.Load(vtap); ok {
			stats = s.(TridentStats)
		}
		if sourceIP != "" {
			stats.Proxy = peerIP.Addr.String()
		}
		stats.IP = remote
		stats.OrgID = orgID
		stats.TeamID = teamID
		stats.VtapID = vtapID
		stats.SyncVersion = version
		stats.SyncAgentType = tType
		stats.SyncLastSeen = time.Now()
		stats.K8sClusterID = k8sClusterID
		stats.TeamShortLcuuid = teamShortLcuuid
		stats.AgentGenesisSyncProcessDataOperation = request.GetProcessData()
		stats.AgentGenesisSyncDataOperation = platformData
		g.tridentStatsMap.Store(vtap, stats)
		g.vtapToVersion.Store(vtap, version)
	}
	return &agent.GenesisSyncResponse{Version: &version}, nil
}

func (g *SynchronizerServer) AgentKubernetesAPISync(ctx context.Context, request *agent.KubernetesAPISyncRequest) (*agent.KubernetesAPISyncResponse, error) {
	remote := ""
	peerIP, _ := peer.FromContext(ctx)
	sourceIP := request.GetSourceIp()
	if sourceIP != "" {
		remote = sourceIP
	} else {
		remote = peerIP.Addr.String()
	}
	vtapID := request.GetAgentId()
	if vtapID == 0 {
		log.Warningf("kubernetes api sync received message with vtap_id 0 from %s", remote)
	}
	version := request.GetVersion()
	if version == 0 {
		log.Warningf("kubernetes api sync ignore message with version 0 from ip: %s, vtap id: %d", remote, vtapID)
		return &agent.KubernetesAPISyncResponse{}, nil
	}
	clusterID := request.GetClusterId()
	if clusterID == "" {
		log.Warningf("kubernetes api sync ignore message with cluster id null from ip: %s, vtap id: %v", remote, vtapID)
		return &agent.KubernetesAPISyncResponse{}, nil
	}
	entries := request.GetEntries()

	var orgID, teamID int
	teamShortLcuuid := request.GetTeamId()
	if teamShortLcuuid == "" {
		orgID = mysqlcommon.DEFAULT_ORG_ID
		teamID = mysqlcommon.DEFAULT_TEAM_ID
	} else {
		t, ok := g.teamShortLcuuidToInfo.Load(teamShortLcuuid)
		if ok {
			orgID = t.(common.TeamInfo).OrgID
			teamID = t.(common.TeamInfo).TeamId
		} else {
			teamShortLcuuidToInfo, err := common.GetTeamShortLcuuidToInfo()
			if err != nil {
				log.Errorf("kubernetes api sync from %s team_id %s vtap get team info failed: %s", remote, teamShortLcuuid, err.Error())
				return &agent.KubernetesAPISyncResponse{}, nil
			}
			teamInfo, ok := teamShortLcuuidToInfo[teamShortLcuuid]
			if !ok {
				log.Errorf("kubernetes api sync %s team_id %s not found team info", remote, teamShortLcuuid)
				return &agent.KubernetesAPISyncResponse{}, nil
			}
			orgID = teamInfo.OrgID
			teamID = teamInfo.TeamId
			for k, v := range teamShortLcuuidToInfo {
				g.teamShortLcuuidToInfo.Store(k, v)
			}
		}
	}
	vtap := fmt.Sprintf("%d-%d", orgID, vtapID)

	var stats TridentStats
	if s, ok := g.tridentStatsMap.Load(vtap); ok {
		stats = s.(TridentStats)
	}
	if sourceIP != "" {
		stats.Proxy = peerIP.Addr.String()
	}
	stats.IP = remote
	stats.OrgID = orgID
	stats.TeamID = teamID
	stats.VtapID = vtapID
	stats.K8sClusterID = clusterID
	stats.K8sLastSeen = time.Now()
	stats.K8sVersion = version
	stats.TeamShortLcuuid = teamShortLcuuid
	g.tridentStatsMap.Store(vtap, stats)
	now := time.Now()
	if vtapID != 0 {
		if lastTime, ok := g.clusterIDToLastSeen.Load(clusterID); ok {
			if now.Sub(lastTime.(time.Time)).Seconds() >= g.cfg.AgingTime {
				g.clusterIDToVersion.Store(clusterID, uint64(0))
			}
		}
		var localVersion uint64 = 0
		lVersion, ok := g.clusterIDToVersion.Load(clusterID)
		if ok {
			localVersion = lVersion.(uint64)
		}
		log.Infof("kubernetes api sync received version %v -> %v from ip %s vtap_id %v len %v", localVersion, version, remote, vtapID, len(entries), logger.NewORGPrefix(orgID))

		// 如果version有更新，但消息中没有任何kubernetes数据，触发vtap重新上报数据
		if localVersion != version && len(entries) == 0 {
			return &agent.KubernetesAPISyncResponse{Version: &localVersion}, nil
		}

		// 正常推送消息到队列中
		g.k8sQueue.Put(common.K8SRPCMessage{
			Peer:         remote,
			ORGID:        orgID,
			VtapID:       vtapID,
			MessageType:  0,
			AgentMessage: request,
		})

		// 更新内存中的last_seen和version
		g.clusterIDToLastSeen.Store(clusterID, now)
		g.clusterIDToVersion.Store(clusterID, version)
		return &agent.KubernetesAPISyncResponse{Version: &version}, nil
	} else {
		log.Infof("kubernetes api sync received version %v from ip %s no vtap_id", version, remote, logger.NewORGPrefix(orgID))
		//正常上报数据，才推送消息到队列中
		if len(entries) > 0 {
			g.k8sQueue.Put(common.K8SRPCMessage{
				Peer:         remote,
				ORGID:        orgID,
				VtapID:       vtapID,
				MessageType:  0,
				AgentMessage: request,
			})
		}
		// 采集器未自动发现时，触发trident上报完整数据
		return &agent.KubernetesAPISyncResponse{}, nil
	}
}
