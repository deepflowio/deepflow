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

package recorder

import (
	"context"

	"github.com/op/go-logging"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

var log = logging.MustGetLogger("recorder")

type Recorder struct {
	cfg config.RecorderConfig
	ctx context.Context

	org             *common.ORG
	domainRefresher *domain
}

func NewRecorder(ctx context.Context, cfg config.RecorderConfig, eventQueue *queue.OverwriteQueue, orgID int, domainLcuuid, domainName string) *Recorder {
	org, err := common.NewORG(orgID)
	if err != nil {
		log.Errorf("failed to create org object: %s", err.Error())
		return nil
	}
	return &Recorder{
		cfg: cfg,
		ctx: ctx,

		org:             org,
		domainRefresher: newDomain(ctx, cfg, eventQueue, org, domainLcuuid, domainName),
	}
}

func (r *Recorder) Refresh(target string, cloudData cloudmodel.Resource) error {
	return r.domainRefresher.Refresh(target, cloudData)
}
