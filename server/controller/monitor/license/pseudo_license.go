/*
 * Copyright (c) 2022 Yunshan Networks
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
	"strconv"
	"strings"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/monitor/config"
)

var log = logging.MustGetLogger("monitor.license")

var VTAP_LICENSE_TYPE_DEFAULT = common.VTAP_LICENSE_TYPE_C
var VTAP_LICENSE_FUNCTIONS = []string{
	strconv.Itoa(common.VTAP_LICENSE_FUNCTION_NETWORK_MONITORING),
	strconv.Itoa(common.VTAP_LICENSE_FUNCTION_APPLICATION_MONITORING),
}

type VTapLicenseAllocation struct {
	cfg config.MonitorConfig
}

func NewVTapLicenseAllocation(cfg config.MonitorConfig) *VTapLicenseAllocation {
	return &VTapLicenseAllocation{cfg: cfg}
}

func (v *VTapLicenseAllocation) Start() {
	go func() {
		for range time.Tick(time.Duration(v.cfg.LicenseCheckInterval) * time.Second) {
			v.allocLicense()
		}
	}()
}

func (v *VTapLicenseAllocation) allocLicense() {
	log.Info("alloc license starting")

	whereSQL := "license_type IS NULL OR license_functions != ?"
	licenseFunctions := strings.Join(VTAP_LICENSE_FUNCTIONS, ",")
	mysql.Db.Model(&mysql.VTap{}).Where(whereSQL, licenseFunctions).Updates(
		map[string]interface{}{
			"license_type":      VTAP_LICENSE_TYPE_DEFAULT,
			"license_functions": licenseFunctions,
		},
	)
	log.Info("alloc license complete")
}
