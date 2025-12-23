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
	"crypto/md5"
	"fmt"
	"math"

	"github.com/golang/protobuf/proto"

	api "github.com/deepflowio/deepflow/message/agent"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type UpgradeEvent struct{}

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

func (e *UpgradeEvent) GetUpgradeFile(upgradePackage string, expectedRevision string, orgID int) (*common.UpgradeData, error) {
	if upgradePackage == "" {
		return nil, fmt.Errorf("image(%s) file does not exist", upgradePackage)
	}
	db, err := metadb.GetDB(orgID)
	if err != nil {
		return nil, fmt.Errorf("get db vtapRepo(name=%s) failed, %s", upgradePackage, err)
	}

	cacheKey := fmt.Sprintf("%d-%s", orgID, upgradePackage)
	imageCace, found := trisolaris.GetImageCache(cacheKey)
	if found {
		return imageCace.(*common.UpgradeData), nil
	}
	vtapRrepo, err := dbmgr.DBMgr[model.VTapRepo](db.DB).GetFromName(upgradePackage)
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
	// max upgrade data packet size is 1024KB, so use half mega byte step
	step := uint64(common.HALF_MEGA_BYTE)
	pktCount := uint32(math.Ceil(float64(totalLen) / float64(step)))
	cipherStr := md5.Sum(content)
	md5Sum := fmt.Sprintf("%x", cipherStr)
	upgradeData := &common.UpgradeData{
		Content:  content,
		TotalLen: totalLen,
		PktCount: pktCount,
		Md5Sum:   md5Sum,
		Step:     step,
		K8sImage: vtapRrepo.K8sImage,
	}
	trisolaris.SetImageCache(cacheKey, upgradeData)
	return upgradeData, err
}

func (e *UpgradeEvent) Upgrade(r *api.UpgradeRequest, in api.Synchronizer_UpgradeServer) error {
	vtapCacheKey := r.GetCtrlIp() + "-" + r.GetCtrlMac()
	teamIDStr := r.GetTeamId()
	log.Infof("vtap(%s) teamID(%s) starts to upgrade", vtapCacheKey, teamIDStr)
	orgID, teamIDInt := trisolaris.GetOrgInfoByTeamID(teamIDStr)
	gVTapInfo := trisolaris.GetORGVTapInfo(orgID)
	if gVTapInfo == nil {
		log.Errorf("vtap(%s) teamID:%s-%d info not found", vtapCacheKey, teamIDStr, teamIDInt, logger.NewORGPrefix(orgID))
		return sendFailed(in)
	}
	vtapCache := gVTapInfo.GetVTapCache(vtapCacheKey)
	if vtapCache == nil {
		log.Errorf("vtap(%s) teamID:%s-%d cache not found", vtapCacheKey, teamIDStr, teamIDInt, logger.NewORGPrefix(orgID))
		return sendFailed(in)
	}
	upgradeData, err := e.GetUpgradeFile(vtapCache.GetUpgradePackage(), vtapCache.GetExpectedRevision(), orgID)
	if err != nil {
		log.Errorf("vtap(%s) teamID:%s-%d, err:%s", vtapCacheKey, teamIDStr, teamIDInt, err, logger.NewORGPrefix(orgID))
		return sendFailed(in)
	}
	if isPodVTap(vtapCache.GetVTapType()) {
		response := &api.UpgradeResponse{
			Status:   &STATUS_SUCCESS,
			K8SImage: proto.String(upgradeData.K8sImage),
		}
		err = in.Send(response)
		if err != nil {
			log.Errorf("vtap(%s) teamID:%s-%d, err:%s", vtapCacheKey, teamIDStr, teamIDInt, err, logger.NewORGPrefix(orgID))
		}
	} else {
		for start := uint64(0); start < upgradeData.TotalLen; start += upgradeData.Step {
			end := start + upgradeData.Step
			if end > upgradeData.TotalLen {
				end = upgradeData.TotalLen
			}
			response := &api.UpgradeResponse{
				Status:   &STATUS_SUCCESS,
				Content:  upgradeData.Content[start:end],
				Md5:      proto.String(upgradeData.Md5Sum),
				PktCount: proto.Uint32(upgradeData.PktCount),
				TotalLen: proto.Uint64(upgradeData.TotalLen),
			}
			err = in.Send(response)
			if err != nil {
				log.Errorf("vtap(%s) teamID:%s-%d, err:%s", vtapCacheKey, teamIDStr, teamIDInt, err, logger.NewORGPrefix(orgID))
				break
			}

			// if upgrade is canceled/completed, should close stream
			if vtapCache.GetExpectedRevision() == "" {
				log.Warningf("vtap(%s) teamID:%s-%d upgrade is canceled/completed", vtapCacheKey, teamIDStr, teamIDInt, logger.NewORGPrefix(orgID))
				break
			}
		}
	}

	log.Infof("vtap(%s) teamID:%s-%d finishes the upgrade", vtapCacheKey, teamIDStr, teamIDInt, logger.NewORGPrefix(orgID))
	return err
}
