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
	"time"

	"github.com/deepflowio/deepflow/server/controller/cloud"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/manager/config"
	"github.com/deepflowio/deepflow/server/controller/recorder"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type Task struct {
	tCtx         context.Context
	tCancel      context.CancelFunc
	cfg          config.TaskConfig
	Cloud        *cloud.Cloud
	Recorder     *recorder.Recorder
	DomainName   string // 云平台名称
	DomainConfig string // 云平台配置字段config
}

func NewTask(domain mysql.Domain, cfg config.TaskConfig, ctx context.Context, resourceEventQueue *queue.OverwriteQueue) *Task {

	tCtx, tCancel := context.WithCancel(ctx)

	return &Task{
		tCtx:         tCtx,
		tCancel:      tCancel,
		cfg:          cfg,
		Cloud:        cloud.NewCloud(domain, cfg.CloudCfg, tCtx),
		Recorder:     recorder.NewRecorder(domain.Lcuuid, domain.Name, cfg.RecorderCfg, tCtx, resourceEventQueue),
		DomainName:   domain.Name,
		DomainConfig: domain.Config,
	}
}

func (t *Task) Start() {
	t.Recorder.Start()
	t.Cloud.Start()

	go func() {
		ticker := time.NewTicker(time.Duration(t.cfg.ResourceRecorderInterval) * time.Second)
	LOOP:
		for {
			select {
			case <-ticker.C:
				cd := t.Cloud.GetResource()
				log.Debugf("domain (%s) cloud data: %+v", t.DomainName, cd)
				t.Recorder.Refresh(cd)
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
