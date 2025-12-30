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

package genesis

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	ccommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/controller/genesis/grpc"
	kstore "github.com/deepflowio/deepflow/server/controller/genesis/store/kubernetes"
	sstorem "github.com/deepflowio/deepflow/server/controller/genesis/store/sync/mysql"
	sstorer "github.com/deepflowio/deepflow/server/controller/genesis/store/sync/redis"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"gorm.io/gorm"
)

var log = logger.MustGetLogger("genesis")

var GenesisService *Genesis

type Genesis struct {
	redisStore   bool
	ctx          context.Context
	sync         common.GenesisSync
	config       *config.ControllerConfig
	kubernetes   *kstore.GenesisKubernetes
	Synchronizer *grpc.SynchronizerServer
}

func NewGenesis(ctx context.Context, isMaster bool, config *config.ControllerConfig) *Genesis {
	syncQueue := queue.NewOverwriteQueue("genesis-sync-data", config.GenesisCfg.QueueLengths)
	kubernetesQueue := queue.NewOverwriteQueue("genesis-k8s-data", config.GenesisCfg.QueueLengths)

	var enabled bool = true
	var genesisSync common.GenesisSync
	genesisSync = sstorer.NewGenesisSync(ctx, isMaster, syncQueue, config)
	if genesisSync == nil || config.GenesisCfg.Database != common.CONFIG_DB_REDIS {
		enabled = false
		genesisSync = sstorem.NewGenesisSync(ctx, isMaster, syncQueue, config)
	}
	genesisSync.Start()

	genesisK8S := kstore.NewGenesisKubernetes(ctx, isMaster, kubernetesQueue, config)
	genesisK8S.Start()

	synchronizer := grpc.NewGenesisSynchronizerServer(config.GenesisCfg, syncQueue, kubernetesQueue, genesisSync, genesisK8S)
	synchronizer.GenerateCache()
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			synchronizer.GenerateCache()
		}
	}()

	GenesisService = &Genesis{
		ctx:          ctx,
		config:       config,
		sync:         genesisSync,
		kubernetes:   genesisK8S,
		Synchronizer: synchronizer,
		redisStore:   enabled,
	}
	return GenesisService
}

func (g *Genesis) GetRedisStoreEnabled() bool {
	return g.redisStore
}

func (g *Genesis) GetGenesisSyncData(orgID int) common.GenesisSyncDataResponse {
	return g.sync.GetGenesisSyncData(orgID)
}

func (g *Genesis) GetGenesisSyncResponse(orgID int) (common.GenesisSyncDataResponse, error) {
	return g.sync.GetGenesisSyncResponse(orgID)
}

func (g *Genesis) GetKubernetesData(orgID int, clusterID string) (common.KubernetesInfo, bool) {
	return g.kubernetes.GetKubernetesData(orgID, clusterID)
}

func (g *Genesis) GetKubernetesResponse(orgID int, clusterID string) (map[string][][]byte, error) {
	resp := map[string][][]byte{}

	var destIP string
	db, err := metadb.GetDB(orgID)
	if err != nil {
		return resp, fmt.Errorf("get metadb session failed: %s", err.Error())
	}

	var cluster model.GenesisCluster
	err = db.Where("id = ?", clusterID).First(&cluster).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return resp, fmt.Errorf("no vtap report cluster id: %s", clusterID)
		}
		return resp, fmt.Errorf("query cluster (%s) from genesis_cluster failed (%s)", clusterID, err.Error())
	}

	nodeIP := os.Getenv(ccommon.NODE_IP_KEY)
	var azControllerConns []metadbmodel.AZControllerConnection
	err = db.Find(&azControllerConns).Error
	if err != nil {
		return resp, fmt.Errorf("query node (%s) az_controller_connection failed (%s)", nodeIP, err.Error())
	}
	nodeIPToRegion := map[string]string{}
	for _, conn := range azControllerConns {
		nodeIPToRegion[conn.ControllerIP] = conn.Region
	}
	currentRegion, ok := nodeIPToRegion[nodeIP]
	if !ok {
		return resp, fmt.Errorf("node (%s) region not found", nodeIP)
	}
	clusterRegion, ok := nodeIPToRegion[cluster.NodeIP]
	if !ok || clusterRegion != currentRegion {
		return resp, fmt.Errorf("cluster store controller mode (%s) not in current region", cluster.NodeIP)
	}
	if cluster.NodeIP != nodeIP {
		var controller metadbmodel.Controller
		err = db.Where("ip = ? AND state <> ?", cluster.NodeIP, ccommon.CONTROLLER_STATE_EXCEPTION).First(&controller).Error
		if err != nil {
			return resp, fmt.Errorf("query node (%s) controller failed (%s)", cluster.NodeIP, err.Error())
		}
		if controller.PodIP == "" {
			return resp, fmt.Errorf("controller (%s) pod ip is empty", cluster.NodeIP)
		}
		// use pod ip communication in internal region
		destIP = controller.PodIP
	}

	return g.kubernetes.GetKubernetesResponse(orgID, clusterID, destIP)
}
