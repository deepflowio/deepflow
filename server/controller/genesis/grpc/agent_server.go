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

	kyaml "github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
	"google.golang.org/grpc/peer"

	"github.com/deepflowio/deepflow/message/agent"
	"github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlcommon "github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	tcommon "github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
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

func (g *SynchronizerServer) GenerateCache() {
	orgIDs, err := mysql.GetORGIDs()
	if err != nil {
		log.Error("get org ids failed")
		return
	}
	for _, orgID := range orgIDs {
		db, err := mysql.GetDB(orgID)
		if err != nil {
			log.Errorf("get org (%d) mysql session failed", orgID)
			continue
		}
		var agentGroups []model.VTapGroup
		if err := db.Find(&agentGroups).Error; err != nil {
			log.Errorf("get agent groups failed: %s", err.Error(), logger.NewORGPrefix(orgID))
			continue
		}
		var groupConfigs []agent_config.MySQLAgentGroupConfiguration
		if err := db.Find(&groupConfigs).Error; err != nil {
			log.Errorf("get agent group configs failed: %s", err.Error(), logger.NewORGPrefix(orgID))
			continue
		}
		LcuuidToGroup := map[string]model.VTapGroup{}
		for _, group := range agentGroups {
			LcuuidToGroup[group.Lcuuid] = group
		}
		for _, config := range groupConfigs {
			group, ok := LcuuidToGroup[config.AgentGroupLcuuid]
			if !ok {
				log.Warningf("agent group config (ID:%d) not found group", config.ID, logger.NewORGPrefix(orgID))
				continue
			}
			k := koanf.New(".")
			if err := k.Load(rawbytes.Provider([]byte(config.Yaml)), kyaml.Parser()); err != nil {
				log.Errorf("parse agent config lcuuid (%s) yaml (%s) failed", config.Lcuuid, config.Yaml, logger.NewORGPrefix(orgID))
				continue
			}
			if !k.Bool(tcommon.CONFIG_KEY_WORKLOAD_RESOURCE_ENABLED) {
				log.Debugf("agent group configuration (ID:%d) workload resource sync disabled", config.ID, logger.NewORGPrefix(orgID))
				continue
			}
			key := fmt.Sprintf("%d-%s", orgID, group.ShortUUID)
			if _, ok := g.workloadResourceEnabledCache.Get(key); !ok {
				var vtaps []model.VTap
				db.Select("id").Where("vtap_group_lcuuid = ?", config.AgentGroupLcuuid).Find(&vtaps)
				for _, vtap := range vtaps {
					g.workloadResourceChangeEnabledCache.SetDefault(fmt.Sprintf("%d-%d", orgID, vtap.ID), nil)
				}
			}
			if group.ID == 1 && group.Name == "default" {
				g.workloadResourceEnabledCache.SetDefault(fmt.Sprintf("%d-", orgID), true)
			}
			g.workloadResourceEnabledCache.SetDefault(key, true)
			g.workloadResourceEnabledCache.SetDefault(fmt.Sprintf("%d-%s", orgID, group.Name), true)
		}
	}
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

	var refresh bool
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
			timeSub := now.Sub(lastTime).Seconds()
			if timeSub >= agingTime {
				g.vtapToVersion.Store(vtap, uint64(0))
			}
			refresh = timeSub >= g.cfg.AgentHeartBeat*2
		}
		g.vtapToLastSeen.Store(vtap, now)
		lVersion, ok := g.vtapToVersion.Load(vtap)
		if ok {
			localVersion = lVersion.(uint64)
		}
	}

	var vtapKey string
	vtapInfo := request.GetAgentInfo()
	groupShortLcuuid := vtapInfo.GetGroupId()
	vtapIP := vtapInfo.GetIp()
	vtapMac := vtapInfo.GetMac()
	if vtapIP != "" && vtapMac != "" {
		vtapKey = fmt.Sprintf("%s-%s", vtapIP, vtapMac)
	}
	_, enabled := g.workloadResourceEnabledCache.Get(fmt.Sprintf("%d-%s", orgID, groupShortLcuuid))

	platformData := request.GetPlatformData()
	if version == localVersion || platformData == nil {
		// If the worload-v is modified to be enabled during the period of continuous heartbeat,
		// it will trigger the re-reporting of the full data.
		if _, ok := g.workloadResourceChangeEnabledCache.Get(vtap); ok {
			g.vtapToVersion.Store(vtap, uint64(0))
			g.workloadResourceChangeEnabledCache.Delete(vtap)
			log.Debugf("genesis sync re-reporting from ip %s vtap_id %v", remote, vtapID, logger.NewORGPrefix(orgID))
			return &agent.GenesisSyncResponse{}, nil
		}

		log.Debugf("genesis sync renew version %v from ip %s vtap_id %v", version, remote, vtapID, logger.NewORGPrefix(orgID))
		g.genesisSyncQueue.Put(
			common.VIFRPCMessage{
				Key:                     vtapKey,
				Peer:                    remote,
				VtapID:                  vtapID,
				ORGID:                   orgID,
				TeamID:                  uint32(teamID),
				MessageType:             common.TYPE_RENEW,
				AgentMessage:            request,
				StorageRefresh:          refresh,
				WorkloadResourceEnabled: enabled,
			},
		)
		return &agent.GenesisSyncResponse{Version: &localVersion}, nil
	}

	log.Infof("genesis sync received version %v -> %v from ip %s vtap_id %v", localVersion, version, remote, vtapID, logger.NewORGPrefix(orgID))
	g.genesisSyncQueue.Put(
		common.VIFRPCMessage{
			Key:                     vtapKey,
			Peer:                    remote,
			VtapID:                  vtapID,
			ORGID:                   orgID,
			TeamID:                  uint32(teamID),
			K8SClusterID:            k8sClusterID,
			MessageType:             common.TYPE_UPDATE,
			AgentMessage:            request,
			WorkloadResourceEnabled: enabled,
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
		stats.GroupShortLcuuid = groupShortLcuuid
		stats.AgentGenesisSyncProcessDataOperation = request.GetProcessData()
		stats.SyncResouceEnabled = enabled
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
