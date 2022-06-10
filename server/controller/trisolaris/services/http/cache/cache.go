package cache

import (
	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	"server/controller/trisolaris"
	"server/controller/trisolaris/server/http"
	"server/controller/trisolaris/server/http/common"
)

var log = logging.MustGetLogger("trisolaris/cache")

const (
	VTAP_CHANGED          = "vtap"
	ANALYZER_CHANGED      = "analyzer"
	PLATFORM_DATA_CHANGED = "platform_data"
	FLOW_ACL_CHANGED      = "flow_acl "
	GROUP_CHANGED         = "group"
	TAP_TYPE_CHANGED      = "tap_type"
	SERVICE_CHANGED       = "service"
)

func init() {
	http.Register(NewCacheService())
}

type CacheService struct{}

func NewCacheService() *CacheService {
	return &CacheService{}
}

func PutCache(c *gin.Context) {
	log.Debug(c.GetQueryArray("type"))
	if changedTypes, ok := c.GetQueryArray("type"); ok {
		for _, changedType := range changedTypes {
			switch changedType {
			case PLATFORM_DATA_CHANGED:
				trisolaris.PutPlatformData()
			case ANALYZER_CHANGED:
				trisolaris.PutNodeInfo()
			case VTAP_CHANGED:
				trisolaris.PutVTapCache()
			case TAP_TYPE_CHANGED:
				trisolaris.PutTapType()
			}
		}
	}
	common.Response(c, nil, common.NewReponse("SUCCESS", "", nil, ""))
}

func (*CacheService) Register(mux *gin.Engine) {
	mux.PUT("v1/caches/", PutCache)
}
