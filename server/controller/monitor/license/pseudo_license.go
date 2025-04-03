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

package license

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/monitor/config"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("monitor.license")

var VTAP_LICENSE_TYPE_DEFAULT = common.VTAP_LICENSE_TYPE_A
var VTAP_LICENSE_FUNCTIONS = []string{
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_NET_NPB),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_NET_NPMD),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_NET_DPDK),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_TRACE_NET),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_TRACE_SYS),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_TRACE_APP),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_TRACE_IO),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_TRACE_BIZ),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_PROFILE_CPU),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_PROFILE_RAM),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_PROFILE_INT),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_LEGACY_METRIC),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_LEGACY_LOG),
	strconv.Itoa(common.AGENT_LICENSE_FUNCTION_LEGACY_PROBE),
}

type VTapLicenseAllocation struct {
	vCtx    context.Context
	vCancel context.CancelFunc
	cfg     config.MonitorConfig
}

func NewVTapLicenseAllocation(cfg config.MonitorConfig, ctx context.Context) *VTapLicenseAllocation {
	vCtx, vCancel := context.WithCancel(ctx)
	return &VTapLicenseAllocation{
		vCtx:    vCtx,
		vCancel: vCancel,
		cfg:     cfg,
	}
}

func (v *VTapLicenseAllocation) Start(sCtx context.Context) {
	log.Info("vtap license allocation and check start")
	go func() {
		ticker := time.NewTicker(time.Duration(v.cfg.LicenseCheckInterval) * time.Second)
		defer ticker.Stop()
	LOOP:
		for {
			select {
			case <-ticker.C:
				if err := metadb.DoOnAllDBs(func(db *metadb.DB) error {
					v.allocLicense(db)
					return nil
				}); err != nil {
					log.Error(err)
				}
			case <-sCtx.Done():
				break LOOP
			case <-v.vCtx.Done():
				break LOOP
			}
		}
	}()
}

func (v *VTapLicenseAllocation) Stop() {
	if v.vCancel != nil {
		v.vCancel()
	}
	log.Info("vtap license allocation and check stopped")
}

func (v *VTapLicenseAllocation) allocLicense(orgDB *metadb.DB) {
	log.Info("alloc license starting", orgDB.LogPrefixORGID)

	whereSQL := "license_functions != ?"
	licenseFunctions := strings.Join(VTAP_LICENSE_FUNCTIONS, ",")
	orgDB.Model(&metadbmodel.VTap{}).Where(whereSQL, licenseFunctions).Updates(
		map[string]interface{}{
			"license_type":      VTAP_LICENSE_TYPE_DEFAULT,
			"license_functions": licenseFunctions,
		},
	)
	log.Info("alloc license complete", orgDB.LogPrefixORGID)
}

func GetSupportedLicenseFunctions(vtapType int) []int {
	return []int{}
}
