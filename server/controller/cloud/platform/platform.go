package platform

import (
	"errors"
	"fmt"

	logging "github.com/op/go-logging"

	"github.com/metaflowys/metaflow/server/controller/cloud/aliyun"
	"github.com/metaflowys/metaflow/server/controller/cloud/baidubce"
	"github.com/metaflowys/metaflow/server/controller/cloud/config"
	"github.com/metaflowys/metaflow/server/controller/cloud/genesis"
	"github.com/metaflowys/metaflow/server/controller/cloud/kubernetes"
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/cloud/qingcloud"
	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

var log = logging.MustGetLogger("cloud.platform")

type Platform interface {
	CheckAuth() error
	GetCloudData() (model.Resource, error)
}

func NewPlatform(domain mysql.Domain, cfg config.CloudConfig) (Platform, error) {
	var platform Platform
	var err error

	switch domain.Type {
	case common.ALIYUN:
		platform, err = aliyun.NewAliyun(domain)
	case common.GENESIS:
		platform, err = genesis.NewGenesis(domain, cfg)
	case common.QINGCLOUD:
		platform, err = qingcloud.NewQingCloud(domain)
	case common.BAIDU_BCE:
		platform, err = baidubce.NewBaiduBce(domain)
	case common.KUBERNETES:
		platform, err = kubernetes.NewKubernetes(domain)
	// TODO: other platform
	default:
		return nil, errors.New(fmt.Sprintf("domain type (%d) not supported", domain.Type))
	}
	return platform, err
}
