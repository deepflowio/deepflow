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

package monitor

import (
	"context"
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mconfig "github.com/deepflowio/deepflow/server/controller/monitor/config"
)

type RegionCheck struct {
	cfg mconfig.MonitorConfig
}

func NewRegionCheck(cfg *config.ControllerConfig) *RegionCheck {
	return &RegionCheck{
		cfg: cfg.MonitorCfg,
	}
}

func (c *RegionCheck) Start(ctx context.Context) {
	log.Info("region check start")
	go func() {
		ticker := time.NewTicker(time.Duration(c.cfg.SyncDefaultORGDataInterval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.SyncDefaultOrgData()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *RegionCheck) SyncDefaultOrgData() {
	log.Infof("weiqiang sync default org data")
	var regions []mysql.Region
	if err := mysql.DefaultDB.Where("create_method = ?", common.CREATE_METHOD_USER_DEFINE).Find(&regions).Error; err != nil {
		log.Error(err)
	}

	if err := mysql.SyncDefaultORGData("name", regions,
		mysql.WithHardDelete(),
		mysql.WithWhereCondition("create_method = ?", common.CREATE_METHOD_USER_DEFINE),
	); err != nil {
		log.Error(err)
	}
}
