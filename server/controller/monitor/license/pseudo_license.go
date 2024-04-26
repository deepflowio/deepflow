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

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/monitor/config"
)

var log = logging.MustGetLogger("monitor.license")

var VTAP_LICENSE_TYPE_DEFAULT = common.VTAP_LICENSE_TYPE_A
var VTAP_LICENSE_FUNCTIONS = []string{
	strconv.Itoa(common.VTAP_LICENSE_FUNCTION_NETWORK_MONITORING),
	strconv.Itoa(common.VTAP_LICENSE_FUNCTION_CALL_MONITORING),
	strconv.Itoa(common.VTAP_LICENSE_FUNCTION_FUNCTION_MONITORING),
	strconv.Itoa(common.VTAP_LICENSE_FUNCTION_APPLICATION_MONITORING),
	strconv.Itoa(common.VTAP_LICENSE_FUNCTION_INDICATOR_MONITORING),
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

func (v *VTapLicenseAllocation) Start() {
	log.Info("vtap license allocation and check start")
	go func() {
		for range time.Tick(time.Duration(v.cfg.LicenseCheckInterval) * time.Second) {
			if err := mysql.GetDBs().DoOnAllDBs(func(db *mysql.DB) error {
				v.allocLicense(db)
				return nil
			}); err != nil {
				log.Error(err)
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

func (v *VTapLicenseAllocation) allocLicense(orgDB *mysql.DB) {
	log.Info("ORG(id=%d database=%s) alloc license starting", orgDB.ORGID, orgDB.Name)

	whereSQL := "license_type IS NULL OR license_functions != ?"
	licenseFunctions := strings.Join(VTAP_LICENSE_FUNCTIONS, ",")
	orgDB.Model(&mysql.VTap{}).Where(whereSQL, licenseFunctions).Updates(
		map[string]interface{}{
			"license_type":      VTAP_LICENSE_TYPE_DEFAULT,
			"license_functions": licenseFunctions,
		},
	)
	log.Info("ORG(id=%d database=%s) alloc license complete", orgDB.ORGID, orgDB.Name)
}

func GetSupportedLicenseType(vtapType int) []int {
	if vtapType == common.VTAP_TYPE_DEDICATED {
		return []int{}
	}
	return []int{common.VTAP_LICENSE_TYPE_A}
}
