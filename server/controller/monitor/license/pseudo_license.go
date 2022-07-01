package license

import (
	"strconv"
	"strings"
	"time"

	logging "github.com/op/go-logging"

	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/monitor/config"
)

var log = logging.MustGetLogger("monitor.license")

var VTAP_LICENSE_TYPE_DEFAULT = common.VTAP_LICENSE_TYPE_C
var VTAP_LICENSE_FUNCTIONS = []string{
	strconv.Itoa(common.VTAP_LICENSE_FUNCTION_APPLICATION_MONITORING),
	strconv.Itoa(common.VTAP_LICENSE_FUNCTION_NETWORK_MONITORING),
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
	mysql.Db.Model(&mysql.VTap{}).Where("license_type IS NULL").Updates(
		map[string]interface{}{
			"license_type":      VTAP_LICENSE_TYPE_DEFAULT,
			"license_functions": strings.Join(VTAP_LICENSE_FUNCTIONS, ","),
		},
	)
	log.Info("alloc license complete")
}
