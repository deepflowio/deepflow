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

var recorderRefreshTryInterval = 5 // unit: s

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
	cloudTask := cloud.NewCloud(domain, cfg.CloudCfg, tCtx)

	return &Task{
		tCtx:                    tCtx,
		tCancel:                 tCancel,
		cfg:                     cfg,
		Cloud:                   cloudTask,
		Recorder:                recorder.NewRecorder(tCtx, cfg.RecorderCfg, resourceEventQueue, common.DEFAULT_ORG_ID, domain.Lcuuid),
		DomainName:              domain.Name,
		DomainConfig:            domain.Config,
		domainRefreshSignal:     cloudTask.GetDomainRefreshSignal(),
		subDomainRefreshSignals: cloudTask.GetSubDomainRefreshSignals(),
	}
}

func (t *Task) Start() {
	t.Cloud.Start()

	t.startDomainRefreshMonitor()
	if t.Cloud.GetBasicInfo().Type != common.KUBERNETES {
		t.startSubDomainRefreshMonitor()
	}
}

func (t *Task) startDomainRefreshMonitor() {
	go func() {
	LOOP:
		for {
			log.Infof("task (%s) wait for next refresh", t.DomainName)
			t.domainRefreshSignal.Get()
			log.Infof("task (%s) call recorder refresh", t.DomainName)
			if err := t.Recorder.Refresh(recorder.RefreshTargetDomain, t.Cloud.GetResource()); err != nil {
				if errors.Is(err, recorder.RefreshConflictError) {
					log.Warningf("task (%s) refresh conflict, retry after 5 seconds", t.DomainName)
					t.domainRefreshSignal.Put(struct{}{})
					time.Sleep(time.Duration(recorderRefreshTryInterval) * time.Second)
				} else {
					log.Warningf("task (%s) refresh failed: %s", t.DomainName, err.Error())
				}
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
						signal.Get()
						log.Infof("task (%s) sub_domain (%s) call recorder refresh", t.DomainName, lcuuid)

						// TODO cloud 提供接口获取附属容器集群数据
						resource := cloudmodel.Resource{
							SubDomainResources: map[string]cloudmodel.SubDomainResource{lcuuid: t.Cloud.GetResource().SubDomainResources[lcuuid]},
						}
						if err := t.Recorder.Refresh(recorder.RefreshTargetSubDomain, resource); err != nil {
							if errors.Is(err, recorder.RefreshConflictError) {
								log.Warningf("task (%s) sub_domain (%s) refresh conflict, retry after 5 seconds", t.DomainName, lcuuid)
								signal.Put(struct{}{})
								time.Sleep(time.Duration(recorderRefreshTryInterval) * time.Second)
							} else {
								log.Warningf("task (%s) sub_domain (%s) refresh failed: %s", t.DomainName, lcuuid, err.Error())
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
