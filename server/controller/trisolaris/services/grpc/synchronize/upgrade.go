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
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"math"

	"github.com/golang/protobuf/proto"

	api "github.com/deepflowys/deepflow/message/trident"
	"github.com/deepflowys/deepflow/server/controller/trisolaris"
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

func (e *UpgradeEvent) GetUpgradeFile(upgradePackage string) (*UpgradeData, error) {
	if upgradePackage == "" {
		return nil, fmt.Errorf("upgradePackage(%s) file does not exist", upgradePackage)
	}
	content, err := ioutil.ReadFile(upgradePackage)
	if err != nil {
		return nil, fmt.Errorf("trident(%s) file does not exist, err: %s", upgradePackage, err)
	}
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
	log.Infof("vtap(%s) starts to upgrade", vtapCacheKey)
	gVTapInfo := trisolaris.GetGVTapInfo()
	vtapCache := gVTapInfo.GetVTapCache(vtapCacheKey)
	if vtapCache == nil {
		log.Errorf("vtap(%s) cache not found", vtapCacheKey)
		return sendFailed(in)
	}
	upgradeData, err := e.GetUpgradeFile(vtapCache.GetUpgradePackage())
	if err != nil {
		log.Error(err)
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
			log.Errorf("vtap(%s), err:%s", vtapCacheKey, err)
			break
		}
	}

	log.Infof("vtap(%s) finishes the upgrade", vtapCacheKey)
	return err
}
