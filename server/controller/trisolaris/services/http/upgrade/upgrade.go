package upgrade

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	models "github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/trisolaris"
	"github.com/metaflowys/metaflow/server/controller/trisolaris/dbmgr"
	"github.com/metaflowys/metaflow/server/controller/trisolaris/server/http"
	"github.com/metaflowys/metaflow/server/controller/trisolaris/server/http/common"
)

var log = logging.MustGetLogger("trisolaris/upgrade")

func init() {
	http.Register(NewUpgradeService())
}

type UpgradeService struct{}

func NewUpgradeService() *UpgradeService {
	return &UpgradeService{}
}

type Version struct {
	Revision string `json:"REVISION" binding:"required"`
}

func Upgrade(c *gin.Context) {
	lcuuid := c.Param("lcuuid")
	if lcuuid == "" {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, "not find lcuuid param"))
		return
	}
	version := Version{}
	err := c.BindJSON(&version)
	if err != nil {
		log.Error(err)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("%s", err)))
		return
	}
	vtap, err := dbmgr.DBMgr[models.VTap](trisolaris.GetDB()).GetFromLcuuid(lcuuid)
	if err != nil {
		log.Error(err)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("%s", err)))
		return
	}
	key := vtap.CtrlIP + "-" + vtap.CtrlMac
	vTapCache := trisolaris.GetGVTapInfo().GetVTapCache(key)
	if vTapCache == nil {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, "not found vtap cache"))
		return
	}
	vTapCache.UpdateUpgradeRevision(version.Revision)
	log.Infof("%+v", version)
	common.Response(c, nil, common.NewReponse("SUCCESS", "", nil, ""))
}

func (*UpgradeService) Register(mux *gin.Engine) {
	mux.PATCH("v1/deepflow/vtaps/:lcuuid/", Upgrade)
}
