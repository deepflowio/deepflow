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

package tagrecorder

import (
	"context"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/config"
)

var log = logging.MustGetLogger("tagrecorder")

type TagRecorder struct {
	tCtx    context.Context
	tCancel context.CancelFunc
	cfg     config.ControllerConfig
}

func NewTagRecorder(cfg config.ControllerConfig, ctx context.Context) *TagRecorder {
	tCtx, tCancel := context.WithCancel(ctx)
	return &TagRecorder{
		tCtx:    tCtx,
		tCancel: tCancel,
		cfg:     cfg,
	}
}

// 每次执行需要做的事情
func (c *TagRecorder) run() {
	log.Info("tagrecorder run")

	// 调用API获取资源对应的icon_id
	domainToIconID, resourceToIconID, _ := c.UpdateIconInfo()
	c.refresh(domainToIconID, resourceToIconID)
}

func (c *TagRecorder) StartChDictionaryUpdate() {
	go func() {
		for range time.Tick(time.Duration(c.cfg.TagRecorderCfg.Interval) * time.Second) {
			c.UpdateChDictionary()
		}
	}()
}

func (c *TagRecorder) Start() {
	go func() {
		for range time.Tick(time.Duration(c.cfg.TagRecorderCfg.Interval) * time.Second) {
			c.run()
		}
	}()
}

func (t *TagRecorder) Stop() {
	if t.tCancel != nil {
		t.tCancel()
	}
	log.Info("tagrecorder stopped")
}

func (c *TagRecorder) refresh(domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) {
	// 生成各资源更新器，刷新ch数据
	updaters := []ChResourceUpdater{
		NewChRegion(domainLcuuidToIconID, resourceTypeToIconID),
		NewChAZ(domainLcuuidToIconID, resourceTypeToIconID),
		NewChVPC(resourceTypeToIconID),
		NewChDevice(resourceTypeToIconID),
		NewChIPRelation(),
		NewChPodK8sLabel(),
		NewChPodK8sLabels(),
		NewChPodServiceK8sLabel(),
		NewChPodServiceK8sLabels(),
		NewChChostCloudTag(),
		NewChPodNSCloudTag(),
		NewChChostCloudTags(),
		NewChPodNSCloudTags(),
		NewChOSAppTag(),
		NewChOSAppTags(),
		NewChVTapPort(),
		NewChStringEnum(),
		NewChIntEnum(),
		NewChNodeType(),
		NewChAPPLabel(),
		NewChTargetLabel(),
		NewChPrometheusTargetLabelLayout(),
		NewChPrometheusLabelName(),
		NewChPrometheusMetricNames(),
		NewChPrometheusMetricAPPLabelLayout(),
		NewChNetwork(resourceTypeToIconID),
		NewChTapType(resourceTypeToIconID),
		NewChVTap(resourceTypeToIconID),
		NewChPod(resourceTypeToIconID),
		NewChPodCluster(resourceTypeToIconID),
		NewChPodGroup(resourceTypeToIconID),
		NewChPodNamespace(resourceTypeToIconID),
		NewChPodNode(resourceTypeToIconID),
		NewChLbListener(resourceTypeToIconID),
		NewChPodIngress(resourceTypeToIconID),
		NewChGProcess(resourceTypeToIconID),

		NewChPodK8sAnnotation(),
		NewChPodK8sAnnotations(),
		NewChPodServiceK8sAnnotation(),
		NewChPodServiceK8sAnnotations(),
		NewChPodK8sEnv(),
		NewChPodK8sEnvs(),

		NewChPolicy(),
		NewChNpbTunnel(),
	}
	if c.cfg.RedisCfg.Enabled {
		updaters = append(updaters, NewChIPResource(c.tCtx))
	}
	for _, updater := range updaters {
		updater.SetConfig(c.cfg.TagRecorderCfg)
		isUpdate := updater.Refresh()
		if isUpdate {
			go func() {
				time.Sleep(time.Duration(c.cfg.TagRecorderCfg.DictionaryRefreshInterval+10) * time.Second)
				UpdateChangeView()
			}()
		}
	}
}
