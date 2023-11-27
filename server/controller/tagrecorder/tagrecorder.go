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
	"sync"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/config"
)

var log = logging.MustGetLogger("tagrecorder")

var (
	tagRecorderOnce sync.Once
	tagRecorder     *TagRecorder
)

func GetSingleton() *TagRecorder {
	tagRecorderOnce.Do(func() {
		tagRecorder = new(TagRecorder)
	})
	return tagRecorder
}

type TagRecorder struct {
	tCtx                 context.Context
	tCancel              context.CancelFunc
	cfg                  config.ControllerConfig
	domainLcuuidToIconID map[string]int // TODO
	resourceTypeToIconID map[IconKey]int
}

func (c *TagRecorder) Init(cfg config.ControllerConfig, ctx context.Context) {
	tCtx, tCancel := context.WithCancel(ctx)
	c.tCtx = tCtx
	c.tCancel = tCancel
	c.cfg = cfg
}

// 每次执行需要做的事情
func (c *TagRecorder) runUpdaters() {
	log.Info("tagrecorder updaters run")

	// 调用API获取资源对应的icon_id
	c.domainLcuuidToIconID, c.resourceTypeToIconID, _ = c.UpdateIconInfo()
	c.refreshByUpdaters()
}

func (c *TagRecorder) StartChDictionaryUpdate() {
	go func() {
		for range time.Tick(time.Duration(c.cfg.TagRecorderCfg.Interval) * time.Second) {
			c.UpdateChDictionary()
		}
	}()
}

func (c *TagRecorder) StartUpdaters() {
	go func() {
		for range time.Tick(time.Duration(c.cfg.TagRecorderCfg.Interval) * time.Second) {
			c.runUpdaters()
		}
	}()
}

func (t *TagRecorder) StopUpdaters() {
	if t.tCancel != nil {
		t.tCancel()
	}
	log.Info("tagrecorder stopped")
}

func (c *TagRecorder) refreshByUpdaters() {
	// 生成各资源更新器，刷新ch数据
	updaters := []ChResourceUpdater{
		NewChRegion(c.domainLcuuidToIconID, c.resourceTypeToIconID),
		NewChVPC(c.resourceTypeToIconID),
		NewChDevice(c.resourceTypeToIconID),
		NewChIPRelation(),
		NewChPodK8sLabel(),
		NewChPodK8sLabels(),
		NewChPodServiceK8sLabel(),
		NewChPodServiceK8sLabels(),
		NewChPodNSCloudTag(),
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
		NewChNetwork(c.resourceTypeToIconID),
		NewChTapType(c.resourceTypeToIconID),
		NewChVTap(c.resourceTypeToIconID),
		NewChPod(c.resourceTypeToIconID),
		NewChPodCluster(c.resourceTypeToIconID),
		NewChPodGroup(c.resourceTypeToIconID),
		NewChPodNamespace(c.resourceTypeToIconID),
		NewChPodNode(c.resourceTypeToIconID),
		NewChLbListener(c.resourceTypeToIconID),
		NewChPodIngress(c.resourceTypeToIconID),
		NewChGProcess(c.resourceTypeToIconID),

		NewChPodK8sAnnotation(),
		NewChPodK8sAnnotations(),
		NewChPodServiceK8sAnnotation(),
		NewChPodServiceK8sAnnotations(),
		NewChPodK8sEnv(),
		NewChPodK8sEnvs(),
		NewChPodService(),
		NewChChost(),
	}
	if c.cfg.RedisCfg.Enabled {
		updaters = append(updaters, NewChIPResource(c.tCtx))
	}
	for _, updater := range updaters {
		updater.SetConfig(c.cfg.TagRecorderCfg)
		updater.Refresh()
	}

}

func (c *TagRecorder) StartSubscribers() {
	log.Info("tagrecorder subscribers started")
	subscribers := []Subscriber{
		NewChAZ(c.domainLcuuidToIconID, c.resourceTypeToIconID),
		NewChChostCloudTag(),
		NewChChostCloudTags(),
	}
	for _, subscriber := range subscribers {
		subscriber.SetConfig(c.cfg.TagRecorderCfg)
		subscriber.Subscribe()
	}
}
