package monitor

import (
	"strconv"
	"strings"
	"time"

	"server/controller/common"
	"server/controller/db/mysql"
	"server/controller/monitor/config"
)

var VTAP_LICENSE_TYPE_DEFAULT = common.VTAP_LICENSE_TYPE_C
var VTAP_LICENSE_FUNCTIONS = []string{
	strconv.Itoa(common.VTAP_LICENSE_FUNCTION_APPLICATION_MONITORING),
	strconv.Itoa(common.VTAP_LICENSE_FUNCTION_NETWORK_MONITORING),
}

type PseudoVTapLicenseAllocation struct {
	cfg config.MonitorConfig
}

func NewPseudoVTapLicenseAllocation(cfg config.MonitorConfig) *PseudoVTapLicenseAllocation {
	return &PseudoVTapLicenseAllocation{cfg: cfg}
}

func (v *PseudoVTapLicenseAllocation) Start() {
	go func() {
		for range time.Tick(time.Duration(v.cfg.LicenseCheckInterval) * time.Second) {
			v.allocLicense()
		}
	}()
}

func (v *PseudoVTapLicenseAllocation) allocLicense() {
	log.Info("alloc license starting")
	mysql.Db.Model(&mysql.VTap{}).Where("license_type IS NULL").Updates(
		map[string]interface{}{
			"license_type":      VTAP_LICENSE_TYPE_DEFAULT,
			"license_functions": strings.Join(VTAP_LICENSE_FUNCTIONS, ","),
		},
	)
	log.Info("alloc license complete")
}
