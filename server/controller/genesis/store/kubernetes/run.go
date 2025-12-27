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

package kubernetes

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	api "github.com/deepflowio/deepflow/message/controller"
	ccommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	"github.com/deepflowio/deepflow/server/controller/genesis/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/statsd"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"google.golang.org/grpc"
)

var log = logger.MustGetLogger("genesis.store.kubernetes")

type GenesisKubernetes struct {
	statsdORGID   int
	isMaster      bool
	data          sync.Map
	mutex         sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	queue         queue.QueueReader
	genesisStatsd statsd.GenesisStatsd
	config        *config.ControllerConfig
}

func NewGenesisKubernetes(ctx context.Context, isMaster bool, queue queue.QueueReader, config *config.ControllerConfig) *GenesisKubernetes {
	ctx, cancel := context.WithCancel(ctx)
	return &GenesisKubernetes{
		data:     sync.Map{},
		ctx:      ctx,
		cancel:   cancel,
		queue:    queue,
		config:   config,
		isMaster: isMaster,
		genesisStatsd: statsd.GenesisStatsd{
			K8SInfoDelay: make(map[string][]float64),
		},
	}
}

func (g *GenesisKubernetes) GetStatter() statsd.StatsdStatter {
	return statsd.StatsdStatter{
		OrgID:   g.statsdORGID,
		Element: statsd.GetGenesisStatsd(g.genesisStatsd),
	}
}

func (g *GenesisKubernetes) receiveKubernetesData(kChan chan common.KubernetesInfo) {
	for {
		select {
		case k := <-kChan:
			g.data.Store(fmt.Sprintf("%d-%s", k.ORGID, k.ClusterID), k)
		case <-g.ctx.Done():
			break
		}
	}
}

func (g *GenesisKubernetes) GetKubernetesData(orgID int, clusterID string) (common.KubernetesInfo, bool) {
	k8sDataInterface, ok := g.data.Load(fmt.Sprintf("%d-%s", orgID, clusterID))
	if !ok {
		log.Warningf("kubernetes data not found cluster id (%s)", clusterID, logger.NewORGPrefix(orgID))
		return common.KubernetesInfo{}, false
	}
	k8sData, ok := k8sDataInterface.(common.KubernetesInfo)
	if !ok {
		log.Error("kubernetes data interface assert failed", logger.NewORGPrefix(orgID))
		return common.KubernetesInfo{}, false
	}
	return k8sData, true
}

func (g *GenesisKubernetes) GetKubernetesResponse(orgID int, clusterID, destIP string) (map[string][][]byte, error) {
	resp := map[string][][]byte{}

	var kubernetesData common.KubernetesInfo
	if destIP == "" {
		data, ok := g.GetKubernetesData(orgID, clusterID)
		if !ok {
			return resp, fmt.Errorf("no found cluster (%s) entries", clusterID)
		}
		kubernetesData = data
	} else {
		grpcServer := net.JoinHostPort(destIP, g.config.GrpcPort)
		conn, err := grpc.Dial(grpcServer, grpc.WithInsecure(), grpc.WithMaxMsgSize(g.config.GrpcMaxMessageLength))
		if err != nil {
			return resp, fmt.Errorf("create grpc connection faild: %s", err.Error())
		}
		defer conn.Close()

		client := api.NewControllerClient(conn)
		reqORGID := uint32(orgID)
		req := &api.GenesisSharingK8SRequest{
			OrgId:     &reqORGID,
			ClusterId: &clusterID,
		}
		ret, err := client.GenesisSharingK8S(g.ctx, req)
		if err != nil {
			return resp, fmt.Errorf("get (%s) genesis sharing k8s failed (%s) ", destIP, err.Error())
		}
		epochStr := ret.GetEpoch()
		epoch, err := time.ParseInLocation(ccommon.GO_BIRTHDAY, epochStr, time.Local)
		if err != nil {
			return resp, fmt.Errorf("genesis api sharing k8s format timestr faild: %s", err.Error())
		}
		kubernetesData = common.KubernetesInfo{
			Epoch:       epoch,
			ErrorMSG:    ret.GetErrorMsg(),
			EntriesJson: ret.GetEntries(),
		}
	}

	if kubernetesData.ErrorMSG != "" {
		return resp, fmt.Errorf("cluster (%s) k8s info grpc Error: %s", clusterID, kubernetesData.ErrorMSG)
	}
	if len(kubernetesData.EntriesJson) == 0 {
		return resp, fmt.Errorf("cluster (%s) k8s entries length is 0", clusterID)
	}

	err := sonic.Unmarshal(kubernetesData.EntriesJson, &resp)
	if err != nil {
		return resp, err
	}

	g.mutex.Lock()
	g.statsdORGID = orgID
	g.genesisStatsd.K8SInfoDelay = map[string][]float64{}
	g.genesisStatsd.K8SInfoDelay[clusterID] = []float64{time.Now().Sub(kubernetesData.Epoch).Seconds()}
	g.mutex.Unlock()
	statsd.MetaStatsd.RegisterStatsdTable(g)

	return resp, nil
}

func (g *GenesisKubernetes) cleanGenesisCluster() {
	orgIDs, err := metadb.GetORGIDs()
	if err != nil {
		log.Warningf("get org ids failed: %s", err.Error())
		return
	}
	for _, orgID := range orgIDs {
		db, err := metadb.GetDB(orgID)
		if err != nil {
			log.Warningf("get metadb session failed: %s", err.Error(), logger.NewORGPrefix(orgID))
			continue
		}
		err = db.Where("1 = 1").Delete(&model.GenesisCluster{}).Error
		if err != nil {
			log.Warningf("clean org (%d) genesis cluster failed: %s", orgID, err.Error(), logger.NewORGPrefix(orgID))
			continue
		}
	}
}

func (g *GenesisKubernetes) Start() {
	kDataChan := make(chan common.KubernetesInfo)

	go g.receiveKubernetesData(kDataChan)

	go func() {
		if g.isMaster {
			g.cleanGenesisCluster()
		}
		kStorage := NewKubernetesStorage(g.ctx, g.config.ListenPort, g.config.ListenNodePort, g.config.GenesisCfg, kDataChan)
		kStorage.Start()

		for {
			info := g.queue.Get().(common.K8SRPCMessage)
			if info.MessageType == common.TYPE_EXIT {
				log.Warningf("k8s from (%s) vtap_id (%v) type (%v) exit", info.Peer, info.VtapID, info.MessageType, logger.NewORGPrefix(info.ORGID))
				break
			}

			if info.Message == nil {
				log.Errorf("k8s message is nil, vtap_id (%d)", info.VtapID, logger.NewORGPrefix(info.ORGID))
				continue
			}

			clusterID := info.Message.GetClusterId()
			version := info.Message.GetVersion()
			errMsg := info.Message.GetErrorMsg()
			entries := info.Message.GetEntries()
			log.Debugf("k8s from %s vtap_id %v received cluster_id %s version %d entries %d", info.Peer, info.VtapID, clusterID, version, len(entries), logger.NewORGPrefix(info.ORGID))

			var interrupted bool
			var entriesJson []byte
			entriesMap := map[string][][]byte{}
			for _, e := range entries {
				eType := e.GetType()
				out, err := common.ParseCompressedInfo(e.GetCompressedInfo())
				if err != nil {
					interrupted = true
					errMsg = fmt.Sprintf("decompress error: %s", err.Error())
					break
				}
				entriesMap[eType] = append(entriesMap[eType], out.Bytes())
			}
			if !interrupted {
				json, err := sonic.Marshal(entriesMap)
				if err != nil {
					errMsg = fmt.Sprintf("marshal error: %s", err.Error())
				} else {
					entriesJson = json
				}
			}

			// 更新和保存内存数据
			kStorage.Add(info.ORGID, common.KubernetesInfo{
				ORGID:       info.ORGID,
				ClusterID:   clusterID,
				Epoch:       time.Now(),
				ErrorMSG:    errMsg,
				Version:     version,
				EntriesJson: entriesJson,
			})
		}
	}()
}

func (s *GenesisKubernetes) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}
