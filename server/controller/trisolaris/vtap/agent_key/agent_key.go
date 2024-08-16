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

package agent_key

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/trisolaris/config"
)

type AgentKeyManager struct{}

func NewAgentKeyManager(db *gorm.DB, cfg *config.Config, orgID int) *AgentKeyManager {
	return &AgentKeyManager{}

}

func (a *AgentKeyManager) InitData() {
}

func (a *AgentKeyManager) GetAgentKey(AgentID int) ([]byte, error) {
	return nil, fmt.Errorf("Community Edition does not support data-side encryption")
}

func (a *AgentKeyManager) MonitorAgentKey() {
}
