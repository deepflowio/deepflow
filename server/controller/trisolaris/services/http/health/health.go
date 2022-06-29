package health

import (
	"github.com/gin-gonic/gin"

	"github.com/metaflowys/metaflow/server/controller/trisolaris/server/http"
	"github.com/metaflowys/metaflow/server/controller/trisolaris/server/http/common"
)

func init() {
	http.Register(NewHealth())
}

func NewHealth() *HealthService {
	return &HealthService{}
}

type HealthService struct{}

func Health(c *gin.Context) {
	common.Response(c, nil, common.NewReponse("SUCCESS", "", nil, ""))
}

func (*HealthService) Register(mux *gin.Engine) {
	mux.GET("/v1/health/", Health)
}
