package querier

import (
	"github.com/gin-gonic/gin"
	logging "github.com/op/go-logging"

	"metaflow/querier/router"
)

var log = logging.MustGetLogger("querier")

type Controller struct{}

func Start() {
	// TODO: 加载配置文件

	// engine加载数据库tag/metric等信息
	Load()
	// 注册router
	r := gin.Default()
	router.QueryRouter(r)
	// TODO: 增加router
	if err := r.Run(":8086"); err != nil {
		log.Errorf("startup service failed, err:%v\n", err)
	}
}
