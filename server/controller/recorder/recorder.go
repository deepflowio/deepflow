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

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

var log = logger.MustGetLogger("recorder")

type Recorder struct {
	cfg config.RecorderConfig
	ctx context.Context

	domainRefresher *domain
}

func NewRecorder(ctx context.Context, cfg config.RecorderConfig, eventQueue *queue.OverwriteQueue, orgID int, domainLcuuid string) *Recorder {
	log.Infof("domain lcuuid: %s, new recorder", domainLcuuid, logger.NewORGPrefix(orgID))
	md, err := common.NewMetadata(cfg, orgID)
	if err != nil {
		log.Errorf("domain lcuuid: %s, failed to create metadata object: %s", domainLcuuid, err.Error(), logger.NewORGPrefix(orgID))
		return nil
	}
	var domain metadbmodel.Domain
	if err := md.DB.Where("lcuuid = ?", domainLcuuid).First(&domain).Error; err != nil {
		log.Errorf("domain lcuuid: %s, failed to get domain from db: %s", domainLcuuid, err.Error(), md.LogPrefixes)
		return nil
	}
	md.SetDomain(domain)

	return &Recorder{
		cfg: cfg,
		ctx: ctx,

		domainRefresher: newDomain(ctx, cfg, eventQueue, md),
	}
}

func (r *Recorder) Refresh(target string, cloudData cloudmodel.Resource) error {
	return r.domainRefresher.Refresh(target, cloudData)
}

func (r *Recorder) Stop() {
	r.CloseStatsd()
}

func (r *Recorder) CloseStatsd() {
	r.domainRefresher.CloseStatsd()
}
