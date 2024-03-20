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
	"crypto/md5"
	"fmt"
	"math"

	"github.com/golang/protobuf/proto"

	api "github.com/deepflowio/deepflow/message/trident"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
)

type PluginEvent struct{}

type PluginData struct {
	content    []byte
	totalLen   uint64
	pktCount   uint32
	md5Sum     string
	step       uint64
	updateTime uint32
}

func NewPluginEvent() *PluginEvent {
	return &PluginEvent{}
}

func (p *PluginEvent) GetPluginData(r *api.PluginRequest) (*PluginData, error) {
	if r.GetPluginType() == 0 || r.GetPluginName() == "" {
		return nil, fmt.Errorf("the plugin request data type(%d) or name(%s) is empty",
			r.GetPluginType(), r.GetPluginName())
	}
	pluginDbMgr := dbmgr.DBMgr[models.Plugin](trisolaris.GetDB())
	plugin, err := pluginDbMgr.GetByOption(
		pluginDbMgr.WithName(r.GetPluginName()),
		pluginDbMgr.WithType(int(r.GetPluginType())),
	)
	if err != nil {
		return nil, fmt.Errorf("get plugin(type=%s, name=%s) from db failed, %s",
			r.GetPluginType(), r.GetPluginName(), err)
	}
	content := plugin.Image
	totalLen := uint64(len(content))
	step := uint64(1024 * 1024)
	pktCount := uint32(math.Ceil(float64(totalLen) / float64(step)))
	md5Sum := fmt.Sprintf("%x", md5.Sum(content))
	return &PluginData{
		content:    content,
		totalLen:   totalLen,
		pktCount:   pktCount,
		md5Sum:     md5Sum,
		step:       step,
		updateTime: uint32(plugin.UpdatedAt.Unix()),
	}, err
}
func sendPluginFailed(in api.Synchronizer_PluginServer) error {
	response := &api.PluginResponse{
		Status: &STATUS_FAILED,
	}
	err := in.Send(response)
	if err != nil {
		log.Error(err)
	}
	return err
}

func (p *PluginEvent) Plugin(r *api.PluginRequest, in api.Synchronizer_PluginServer) error {
	vtapCacheKey := r.GetCtrlIp() + "-" + r.GetCtrlMac()
	teamID := r.GetTeamId()
	orgID := trisolaris.GetOrgIDByTeamID(teamID)
	vtapCache := trisolaris.GetGVTapInfo(orgID).GetVTapCache(vtapCacheKey)
	if vtapCache == nil {
		log.Errorf("agent(%s team_id=%s org_id=%d) cache not found", vtapCacheKey, teamID, orgID)
		return sendPluginFailed(in)
	}
	log.Infof("receive agent(%s team_id=%s org_id=%d) plugin request", vtapCacheKey, teamID, orgID)

	pluginData, err := p.GetPluginData(r)
	if err != nil {
		log.Error(err)
		return sendPluginFailed(in)
	}
	for start := uint64(0); start < pluginData.totalLen; start += pluginData.step {
		end := start + pluginData.step
		if end > pluginData.totalLen {
			end = pluginData.totalLen
		}
		response := &api.PluginResponse{
			Status:     &STATUS_SUCCESS,
			Content:    pluginData.content[start:end],
			Md5:        proto.String(pluginData.md5Sum),
			PktCount:   proto.Uint32(pluginData.pktCount),
			TotalLen:   proto.Uint64(pluginData.totalLen),
			UpdateTime: proto.Uint32(pluginData.updateTime),
		}
		err = in.Send(response)
		if err != nil {
			log.Errorf("send agent(%s team_id=%s org_id=%d) plugin data faild, err:%s", vtapCacheKey, teamID, orgID, err)
			break
		}
	}
	log.Infof("sending plugin data to agent(%s team_id=%s org_id=%d) completed", vtapCacheKey, teamID, orgID)
	return err
}
