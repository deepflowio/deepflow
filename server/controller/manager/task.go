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

package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	cmap "github.com/orcaman/concurrent-map/v2"

	"github.com/deepflowio/deepflow/server/controller/cloud"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/manager/config"
	"github.com/deepflowio/deepflow/server/controller/recorder"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type Task struct {
	tCtx    context.Context
	tCancel context.CancelFunc
	cfg     config.TaskConfig

	Cloud        *cloud.Cloud
	Recorder     *recorder.Recorder
	DomainName   string // 云平台名称
	DomainConfig string // 云平台配置字段config

	// 云平台刷新控制，初始化时本信号自动启动一个 goroutine 定时输入信号，用于定时刷新；
	// kubernetes 类型云平台的 kubernetes_gather，也通过输入到此信号，触发实时刷新。
	domainRefreshSignal *queue.OverwriteQueue
	// 附属容器集群刷新控制，因为定时刷新云平台包含了刷新附属容器集群，所以此信号初始化时不启动定时输入信号 goroutine；
	// kubernetes_gather，通过输入到此信号，触发实时性刷新。
	// TODO 增删与 Cloud.GetResource() 的 SubDomainResources 同步
	subDomainRefreshSignals cmap.ConcurrentMap[string, *queue.OverwriteQueue] // key: subDomainLcuuid
}

func NewTask(domain mysql.Domain, cfg config.TaskConfig, ctx context.Context, resourceEventQueue *queue.OverwriteQueue) *Task {

	tCtx, tCancel := context.WithCancel(ctx)

	return &Task{
		tCtx:         tCtx,
		tCancel:      tCancel,
		cfg:          cfg,
		Cloud:        cloud.NewCloud(domain, cfg.CloudCfg, tCtx),
		Recorder:     recorder.NewRecorder(tCtx, cfg.RecorderCfg, resourceEventQueue, common.DEFAULT_ORG_ID, domain.Lcuuid, domain.Name),
		DomainName:   domain.Name,
		DomainConfig: domain.Config,

		domainRefreshSignal: queue.NewOverwriteQueue(
			fmt.Sprintf("cloud-task-%s", domain.Name),
			1,
			queue.OptionFlushIndicator(time.Duration(cfg.ResourceRecorderInterval)*time.Second), // 定时输入信号，用于定时刷新
		),
		subDomainRefreshSignals: cmap.New[*queue.OverwriteQueue](),
	}
}

func (t *Task) Start() {
	t.Cloud.Start()

	t.startDomainRefreshMonitor()
	if t.Cloud.GetBasicInfo().Type != common.KUBERNETES {
		t.startSubDomainChangeMonitor()
		t.startSubDomainRefreshMonitor()
	}
}

func (t *Task) startDomainRefreshMonitor() {
	go func() {
	LOOP:
		for {
			log.Infof("task (%s) wait for next refresh", t.DomainName) // TODO delete debug log
			t.domainRefreshSignal.Get()
			log.Infof("task (%s) call recorder refresh", t.DomainName)
			log.Infof("task (%s) sub_domain refresh signals: %#v", t.DomainName, t.subDomainRefreshSignals)
			if err := t.Recorder.Refresh(recorder.RefreshTargetDomain, t.Cloud.GetResource()); errors.Is(err, recorder.RefreshConflictError) {
				log.Warningf("task (%s) refresh conflict, retry after 5 seconds", t.DomainName)
				t.domainRefreshSignal.Put(struct{}{})
				time.Sleep(5 * time.Second) // TODO
			}

			select {
			case <-t.tCtx.Done():
				break LOOP
			default:
			}

			log.Infof("task (%s) one loop over", t.DomainName)
		}
	}()
}

func (t *Task) startSubDomainRefreshMonitor() {
	go func() {
		ticker := time.NewTicker(time.Millisecond * 200)
		defer ticker.Stop()

	LOOP:
		for {
			select {
			case <-ticker.C:
				for item := range t.subDomainRefreshSignals.IterBuffered() {
					lcuuid := item.Key
					signal := item.Val

					// TODO 考虑改为并发
					if signal.Len() != 0 {
						// TODO cloud 提供接口获取附属容器集群数据
						resource := cloudmodel.Resource{
							SubDomainResources: map[string]cloudmodel.SubDomainResource{lcuuid: t.Cloud.GetResource().SubDomainResources[lcuuid]},
						}
						if err := t.Recorder.Refresh(recorder.RefreshTargetSubDomain, resource); err == nil {
							signal.Get()
						} else {
							if errors.Is(err, recorder.RefreshConflictError) {
								log.Warningf("task (%s) sub_domain (%s) refresh conflict, retry after 5 seconds", t.DomainName, lcuuid)
								time.Sleep(5 * time.Second) // TODO
							}
						}
					}
				}
			case <-t.tCtx.Done():
				break LOOP
			}
		}
	}()

}

// startSubDomainChangeMonitor maintains the add and delete of sub_domain refresh signals by periodically getting KubernetesGatherTaskMap from cloud
func (t *Task) startSubDomainChangeMonitor() {
	gatherTasks := t.Cloud.GetKubernetesGatherTaskMap()
	for lcuuid := range gatherTasks {
		t.createSubDomainSignalIfNotExists(lcuuid)
	}
	go func() {
		ticker := time.NewTicker(time.Duration(t.cfg.ResourceRecorderInterval) * time.Second)
		defer ticker.Stop()

	LOOP:
		for {
			select {
			case <-ticker.C:
				gatherTasks := t.Cloud.GetKubernetesGatherTaskMap()
				for lcuuid := range gatherTasks {
					t.createSubDomainSignalIfNotExists(lcuuid)
				}
				for lcuuid := range t.subDomainRefreshSignals.Items() {
					if _, ok := gatherTasks[lcuuid]; !ok {
						t.subDomainRefreshSignals.Remove(lcuuid)
					}
				}
			case <-t.tCtx.Done():
				break LOOP
			}
		}
	}()
}

func (t *Task) Stop() {
	t.Cloud.Stop()
	if t.tCancel != nil {
		t.tCancel()
	}
	log.Infof("task (%s) stopped", t.DomainName)
}

func (t *Task) UpdateDomainName(name string) {
	t.DomainName = name
	t.Cloud.UpdateBasicInfoName(name)
}

// 用于向云平台及附属荣集群的刷新信号队列输入信号，触发刷新
// TODO 添加 kubernetes_gather 相关逻辑实现
func (t *Task) PutRefreshSignal(target string, lcuuid string) error {
	log.Infof("task (%s) get a refresh signal, target: %s, lcuuid: %s", t.DomainName, target, lcuuid)
	switch target {
	case "domain":
		t.domainRefreshSignal.Put(struct{}{})
	case "sub_domain":
		signal := t.createSubDomainSignalIfNotExists(lcuuid)
		if signal == nil {
			return errors.New(fmt.Sprintf("task (%s) sub_domain (lcuuid: %s) refresh signal not found", t.DomainName, lcuuid))
		}
		signal.Put(struct{}{})
	default:
	}
	return nil
}

func (t *Task) createSubDomainSignalIfNotExists(lcuuid string) *queue.OverwriteQueue {
	t.subDomainRefreshSignals.SetIfAbsent(
		lcuuid,
		queue.NewOverwriteQueue(fmt.Sprintf("sub-domain-task-%s", lcuuid), 1),
	)
	signal, _ := t.subDomainRefreshSignals.Get(lcuuid)
	return signal
}
