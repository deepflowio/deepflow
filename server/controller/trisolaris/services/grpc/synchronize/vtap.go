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
	"github.com/golang/protobuf/proto"
	context "golang.org/x/net/context"
	"math"

	api "github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	models "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type VTapEvent struct{}

func NewVTapEvent() *VTapEvent {
	return &VTapEvent{}
}

// from 7.0, old version agent is not supported
func (e *VTapEvent) Sync(ctx context.Context, in *api.SyncRequest) (*api.SyncResponse, error) {
	ctrlIP := in.GetCtrlIp()
	ctrlMac := in.GetCtrlMac()
	teamIDStr := in.GetTeamId()
	orgID, teamIDInt := trisolaris.GetOrgInfoByTeamID(teamIDStr)
	if rOrgID := int(in.GetOrgId()); rOrgID != 0 && len(teamIDStr) == 0 {
		orgID = rOrgID
	}
	log.Errorf(
		"ctrlIp is %s, ctrlMac is %s, team_id is (str=%s,int=%d) version is too old, should upgrade",
		ctrlIP, ctrlMac, teamIDStr, teamIDInt, logger.NewORGPrefix(orgID),
	)
	return &api.SyncResponse{
		Status:   &STATUS_FAILED,
		Revision: proto.String(in.GetRevision()),
	}, nil
}

func isPodVTap(vtapType int) bool {
	switch vtapType {
	case VTAP_TYPE_POD_VM, VTAP_TYPE_POD_HOST, VTAP_TYPE_K8S_SIDECAR:
		return true
	default:
		return false
	}
}

type UpgradeEvent struct{}

type UpgradeData struct {
	content  []byte
	totalLen uint64
	pktCount uint32
	md5Sum   string
	step     uint64
	k8sImage string
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

func (e *UpgradeEvent) GetUpgradeFile(upgradePackage string, expectedRevision string, orgID int) (*UpgradeData, error) {
	if upgradePackage == "" {
		return nil, fmt.Errorf("image(%s) file does not exist", upgradePackage)
	}
	db, err := metadb.GetDB(orgID)
	if err != nil {
		return nil, fmt.Errorf("get db vtapRepo(name=%s) failed, %s", upgradePackage, err)
	}

	vtapRrepo, err := dbmgr.DBMgr[models.VTapRepo](db.DB).GetFromName(upgradePackage)
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
		k8sImage: vtapRrepo.K8sImage,
	}, err
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
			K8SImage: proto.String(upgradeData.k8sImage),
		}
		err = in.Send(response)
		if err != nil {
			log.Errorf("vtap(%s) teamID:%s-%d, err:%s", vtapCacheKey, teamIDStr, teamIDInt, err, logger.NewORGPrefix(orgID))
		}
	} else {
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
				log.Errorf("vtap(%s) teamID:%s-%d, err:%s", vtapCacheKey, teamIDStr, teamIDInt, err, logger.NewORGPrefix(orgID))
				break
			}
		}
	}

	log.Infof("vtap(%s) teamID:%s-%d finishes the upgrade", vtapCacheKey, teamIDStr, teamIDInt, logger.NewORGPrefix(orgID))
	return err
}
