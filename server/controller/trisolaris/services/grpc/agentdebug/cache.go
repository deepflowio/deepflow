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
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/trisolaris/vtap"
)

type AgentCacheDebug struct {
	RawData string `json:"DATA"`
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
	return &AgentCacheDebug{
		RawData: fmt.Sprintf("%s", vtapCache),
	}
}
