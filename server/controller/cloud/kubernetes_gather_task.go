/*
 * Copyright (c) 2023 Yunshan Networks
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
	"time"

	"github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather"
	kmodel "github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type KubernetesGatherTask struct {
	kCtx             context.Context
	kCancel          context.CancelFunc
	interval         uint32
	gatherCost       float64
	kubernetesGather *kubernetes_gather.KubernetesGather
	resource         kmodel.KubernetesGatherResource
	basicInfo        kmodel.KubernetesGatherBasicInfo
	SubDomainConfig  string // 附属容器集群配置字段config
}

func NewKubernetesGatherTask(
	ctx context.Context, domain *mysql.Domain, subDomain *mysql.SubDomain, cfg config.CloudConfig, isSubDomain bool) *KubernetesGatherTask {
	kubernetesGather := kubernetes_gather.NewKubernetesGather(domain, subDomain, cfg, isSubDomain)
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
		interval:         cfg.KubernetesGatherInterval,
		kubernetesGather: kubernetesGather,
		SubDomainConfig:  subDomainConfig,
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

func (k *KubernetesGatherTask) Start() {
	go func() {
		k.run()
		ticker := time.NewTicker(time.Second * time.Duration(k.interval))
	LOOP:
		for {
			select {
			case <-ticker.C:
				k.run()
			case <-k.kCtx.Done():
				break LOOP
			}
		}
	}()
}

func (k *KubernetesGatherTask) run() {
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
}

func (k *KubernetesGatherTask) Stop() {
	if k.kCancel != nil {
		k.kCancel()
	}
}
