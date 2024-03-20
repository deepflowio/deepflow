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

type UpgradeEvent struct{}

type UpgradeData struct {
	content  []byte
	totalLen uint64
	pktCount uint32
	md5Sum   string
	step     uint64
}

func NewUpgradeEvent() *UpgradeEvent {
	return &UpgradeEvent{}
}

func sendFailed(in api.Synchronizer_UpgradeServer) error {
	response := &api.UpgradeResponse{
		Status: &STATUS_FAILED,
	}
	err := in.Send(response)
	if err != nil {
		log.Error(err)
	}
	return err
}

func (e *UpgradeEvent) GetUpgradeFile(upgradePackage string, expectedRevision string) (*UpgradeData, error) {
	if upgradePackage == "" {
		return nil, fmt.Errorf("image(%s) file does not exist", upgradePackage)
	}
	vtapRrepo, err := dbmgr.DBMgr[models.VTapRepo](trisolaris.GetDB()).GetFromName(upgradePackage)
	if err != nil {
		return nil, fmt.Errorf("get vtapRepo(name=%s) failed, %s", upgradePackage, err)
	}
	dbRevision := vtapRrepo.RevCount + "-" + vtapRrepo.CommitID
	if dbRevision != expectedRevision {
		return nil, fmt.Errorf("get vtapRepo(name=%s) failed, dbRevision(%s) != expectedRevision(%s)",
			upgradePackage, dbRevision, expectedRevision)
	}
	content := vtapRrepo.Image
	totalLen := uint64(len(content))
	step := uint64(1024 * 1024)
	pktCount := uint32(math.Ceil(float64(totalLen) / float64(step)))
	cipherStr := md5.Sum(content)
	md5Sum := fmt.Sprintf("%x", cipherStr)
	return &UpgradeData{
		content:  content,
		totalLen: totalLen,
		pktCount: pktCount,
		md5Sum:   md5Sum,
		step:     step,
	}, err
}

func (e *UpgradeEvent) Upgrade(r *api.UpgradeRequest, in api.Synchronizer_UpgradeServer) error {
	vtapCacheKey := r.GetCtrlIp() + "-" + r.GetCtrlMac()
	teamIDStr := r.GetTeamId()
	log.Infof("vtap(%s) teamID(%s) starts to upgrade", vtapCacheKey, teamIDStr)
	orgID, teamIDInt := trisolaris.GetOrgInfoByTeamID(teamIDStr)
	gVTapInfo := trisolaris.GetGVTapInfo(orgID)
	if gVTapInfo == nil {
		log.Errorf("vtap(%s) orgID:%s teamID:%s-%d info not found", vtapCacheKey, orgID, teamIDStr, teamIDInt)
		return sendFailed(in)
	}
	vtapCache := gVTapInfo.GetVTapCache(vtapCacheKey)
	if vtapCache == nil {
		log.Errorf("vtap(%s) orgID:%s teamID:%s-%d cache not found", vtapCacheKey, orgID, teamIDStr, teamIDInt)
		return sendFailed(in)
	}
	upgradeData, err := e.GetUpgradeFile(vtapCache.GetUpgradePackage(), vtapCache.GetExpectedRevision())
	if err != nil {
		log.Errorf("vtap(%s) orgID:%s teamID:%s-%d, err:%s", vtapCacheKey, orgID, teamIDStr, teamIDInt, err)
		return sendFailed(in)
	}
	for start := uint64(0); start < upgradeData.totalLen; start += upgradeData.step {
		end := start + upgradeData.step
		if end > upgradeData.totalLen {
			end = upgradeData.totalLen
		}
		response := &api.UpgradeResponse{
			Status:   &STATUS_SUCCESS,
			Content:  upgradeData.content[start:end],
			Md5:      proto.String(upgradeData.md5Sum),
			PktCount: proto.Uint32(upgradeData.pktCount),
			TotalLen: proto.Uint64(upgradeData.totalLen),
		}
		err = in.Send(response)
		if err != nil {
			log.Errorf("vtap(%s) orgID:%s teamID:%s-%d, err:%s", vtapCacheKey, orgID, teamIDStr, teamIDInt, err)
			break
		}
	}

	log.Infof("vtap(%s) orgID:%s teamID:%s-%d finishes the upgrade", vtapCacheKey, orgID, teamIDStr, teamIDInt)
	return err
}
