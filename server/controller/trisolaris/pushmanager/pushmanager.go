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

package pushmanager

import (
	"sync"

	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

type PushManager struct {
	orgToagentC [utils.ORG_ID_INDEX_MAX]*sync.Cond
	ingesterC   *sync.Cond
}

var pushManager *PushManager = NewPushManager()

func NewPushManager() *PushManager {
	orgToagentC := [utils.ORG_ID_INDEX_MAX]*sync.Cond{}
	for index, _ := range orgToagentC {
		orgToagentC[index] = sync.NewCond(&sync.Mutex{})
	}
	return &PushManager{
		orgToagentC: orgToagentC,
		ingesterC:   sync.NewCond(&sync.Mutex{}),
	}
}

func Broadcast(orgID int) {
	if utils.CheckOrgID(orgID) {
		pushManager.orgToagentC[orgID].Broadcast()
	}
}

func IngesterBroadcast() {
	pushManager.ingesterC.Broadcast()
}

func Wait(orgID int) {
	if utils.CheckOrgID(orgID) {
		agentC := pushManager.orgToagentC[orgID]
		agentC.L.Lock()
		agentC.Wait()
		agentC.L.Unlock()
	}
}

func IngesterWait() {
	pushManager.ingesterC.L.Lock()
	pushManager.ingesterC.Wait()
	pushManager.ingesterC.L.Unlock()
}
