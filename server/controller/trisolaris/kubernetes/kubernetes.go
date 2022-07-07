package kubernetes

import (
	"sync"

	"github.com/op/go-logging"
	"gorm.io/gorm"

	. "github.com/metaflowys/metaflow/server/controller/common"
	models "github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/trisolaris/dbmgr"
)

var log = logging.MustGetLogger("trisolaris.kubernetes")

type KubernetesInfo struct {
	mutex             sync.RWMutex
	clusterIDToDomain map[string]string
	db                *gorm.DB
}

func NewKubernetesInfo(db *gorm.DB) *KubernetesInfo {
	DomainMgr := dbmgr.DBMgr[models.Domain](db)
	dbDomains, _ := DomainMgr.GetBatchFromTypes([]int{KUBERNETES})
	clusterIDToDomain := make(map[string]string)
	for _, dbDomain := range dbDomains {
		clusterIDToDomain[dbDomain.ClusterID] = dbDomain.Lcuuid
	}

	return &KubernetesInfo{clusterIDToDomain: clusterIDToDomain}
}

func (k *KubernetesInfo) CacheClusterID(clusterID string) {
	k.mutex.Lock()
	_, ok := k.clusterIDToDomain[clusterID]
	if !ok {
		k.clusterIDToDomain[clusterID] = ""
		log.Infof("cache cluster_id (%s)", clusterID)
		//TODO: start go routing to create domain
	}
	k.mutex.Unlock()
	return
}
