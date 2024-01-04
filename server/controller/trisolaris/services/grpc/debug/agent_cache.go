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
	"encoding/json"
	"time"

	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/vtap"
)

type AgentCacheDebug struct {
	BootTime             string `json:"boot_time"`
	SyncedControllerTime string `json:"synced_controller_time"`
	SyncedTSDBTime       string `json:"synced_tsdb_time"`
	ControllerIP         string `json:"controller_ip"`
	CurControllerIP      string `json:"cur_controller_ip"`
	TSDBIP               string `json:"tsdb_ip"`
	CurTSDBIP            string `json:"cur_tsdb_ip"`
}

func (a *AgentCacheDebug) Marshal() []byte {
	if a == nil {
		return nil
	}
	v, err := json.Marshal(*a)
	if err != nil {
		log.Error(err)
		return nil
	}

	return v
}

func NewAgentCacheDebug(vtapCache *vtap.VTapCache) *AgentCacheDebug {
	var syncedControllerStr, syncedTSDBStr, bootTimeStr string
	syncedController := vtapCache.GetSyncedControllerAt()
	if syncedController != nil {
		syncedControllerStr = syncedController.Format(GO_BIRTHDAY)
	}
	syncedTSDB := vtapCache.GetSyncedTSDBAt()
	if syncedTSDB != nil {
		syncedTSDBStr = syncedTSDB.Format(GO_BIRTHDAY)
	}
	bootTime := vtapCache.GetBootTime()
	if bootTime != 0 {
		bootTimeStr = time.Unix(int64(bootTime), 0).Format(GO_BIRTHDAY)
	}
	return &AgentCacheDebug{
		BootTime:             bootTimeStr,
		SyncedControllerTime: syncedControllerStr,
		SyncedTSDBTime:       syncedTSDBStr,
		ControllerIP:         vtapCache.GetControllerIP(),
		TSDBIP:               vtapCache.GetTSDBIP(),
		CurControllerIP:      vtapCache.GetCurControllerIP(),
		CurTSDBIP:            vtapCache.GetCurTSDBIP(),
	}
}
