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

package cloud

import (
	"context"
	"fmt"
	"time"

	"github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather"
	kmodel "github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type KubernetesGatherTask struct {
	kCtx                context.Context
	kCancel             context.CancelFunc
	gatherCost          float64
	SubDomainConfig     string // 附属容器集群配置字段config
	resource            kmodel.KubernetesGatherResource
	basicInfo           kmodel.KubernetesGatherBasicInfo
	gatherRefreshSignal *queue.OverwriteQueue
	kubernetesGather    *kubernetes_gather.KubernetesGather
}

func NewKubernetesGatherTask(
	ctx context.Context, db *mysql.DB, domain *mysql.Domain, subDomain *mysql.SubDomain, cfg config.CloudConfig, isSubDomain bool) *KubernetesGatherTask {
	kubernetesGather := kubernetes_gather.NewKubernetesGather(db, domain, subDomain, cfg, isSubDomain)
	if kubernetesGather == nil {
		log.Errorf("kubernetes_gather task (%s) init faild", domain.Name)
		return nil
	}
	subDomainConfig := ""
	if subDomain != nil {
		subDomainConfig = subDomain.Config
	}

	kCtx, kCancel := context.WithCancel(ctx)
	return &KubernetesGatherTask{
		basicInfo: kmodel.KubernetesGatherBasicInfo{
			Name:                  kubernetesGather.Name,
			Lcuuid:                kubernetesGather.Lcuuid,
			ClusterID:             kubernetesGather.ClusterID,
			PortNameRegex:         kubernetesGather.PortNameRegex,
			PodNetIPv4CIDRMaxMask: kubernetesGather.PodNetIPv4CIDRMaxMask,
			PodNetIPv6CIDRMaxMask: kubernetesGather.PodNetIPv6CIDRMaxMask,
		},
		resource: kmodel.KubernetesGatherResource{
			ErrorState: common.RESOURCE_STATE_CODE_SUCCESS,
		},
		kCtx:             kCtx,
		kCancel:          kCancel,
		kubernetesGather: kubernetesGather,
		SubDomainConfig:  subDomainConfig,
		gatherRefreshSignal: queue.NewOverwriteQueue(
			fmt.Sprintf("kubernetes-gather-%s", kubernetesGather.Name),
			1,
			queue.OptionFlushIndicator(time.Duration(cfg.KubernetesGatherInterval)*time.Second), // 定时输入信号，用于定时刷新
		),
	}
}

func (k *KubernetesGatherTask) GetBasicInfo() kmodel.KubernetesGatherBasicInfo {
	return k.basicInfo
}

func (k *KubernetesGatherTask) GetResource() kmodel.KubernetesGatherResource {
	return k.resource
}

func (k *KubernetesGatherTask) GetGatherCost() float64 {
	return k.gatherCost
}

func (k *KubernetesGatherTask) PutRefreshSignal(version int) error {
	log.Infof("kubernetes gather (%s) get a refresh version (%d)", k.kubernetesGather.Name, version)
	k.gatherRefreshSignal.Put(struct{}{})
	return nil
}

func (k *KubernetesGatherTask) Start(rSignal *queue.OverwriteQueue) {
	go func() {
		k.run(rSignal)
	LOOP:
		for {
			k.gatherRefreshSignal.Get()
			k.run(rSignal)
			select {
			case <-k.kCtx.Done():
				break LOOP
			default:
			}
		}
	}()
}

func (k *KubernetesGatherTask) run(rSignal *queue.OverwriteQueue) {
	startTime := time.Now()
	log.Infof("kubernetes gather (%s) assemble data starting", k.kubernetesGather.Name)
	kResource, err := k.kubernetesGather.GetKubernetesGatherData()
	// 这里因为任务内部没有对成功的状态赋值状态码，在这里统一处理了
	if err != nil {
		kResource.ErrorMessage = err.Error()
		if kResource.ErrorState == 0 {
			kResource.ErrorState = common.RESOURCE_STATE_CODE_EXCEPTION
		}
	} else {
		kResource.ErrorState = common.RESOURCE_STATE_CODE_SUCCESS
	}
	k.resource = kResource
	log.Infof("kubernetes gather (%s) assemble data complete", k.kubernetesGather.Name)
	k.gatherCost = time.Now().Sub(startTime).Seconds()
	if rSignal == nil {
		log.Errorf("kubernetes gather (%s) refresh signal is nil")
		return
	}
	rSignal.Put(struct{}{})
}

func (k *KubernetesGatherTask) Stop() {
	if k.kCancel != nil {
		k.kCancel()
	}
}
