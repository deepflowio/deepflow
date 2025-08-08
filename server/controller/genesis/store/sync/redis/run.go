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

package redis

import (
	"context"

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type GenesisSync struct{}

func NewGenesisSync(ctx context.Context, isMaster bool, queue queue.QueueReader, config *config.ControllerConfig) *GenesisSync {
	return nil
}

func (g *GenesisSync) GetGenesisSyncData(orgID int) common.GenesisSyncDataResponse {
	return common.GenesisSyncDataResponse{}
}

func (g *GenesisSync) GetGenesisSyncResponse(orgID int) (common.GenesisSyncDataResponse, error) {
	return common.GenesisSyncDataResponse{}, nil
}

func (g *GenesisSync) Start() {}
