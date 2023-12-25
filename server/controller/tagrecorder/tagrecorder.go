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

package tagrecorder

import (
	"context"
	"fmt"
	"net"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/common"
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
	selfController, err := common.GetSelfController()
	if err != nil {
		log.Error(err)
		return
	}
	masterIP, port, _, err := common.GetMasterControllerHostPort()
	if err != nil {
		log.Error(err)
		return
	}
	url := fmt.Sprintf("http://%s/v1/tagrecorder/check/", net.JoinHostPort(masterIP, fmt.Sprintf("%d", port)))
	if selfController.NodeType == common.CONTROLLER_NODE_TYPE_MASTER {
		log.Info("tagrecorder check data run")
		t := time.Now()
		c.checkData()
		if _, err = common.CURLPerform("PATCH", url, nil); err != nil {
			log.Error(err)
		}
		log.Infof("tagrecorder check data end, total time since: %v", time.Since(t))
	} else {
		for range time.Tick(time.Second) {
			resp, err := common.CURLPerform("GET", url, nil)
			if err != nil {
				log.Error(err)
			}
			isCheck := resp.Get("DATA").Get("IS_CHECK").MustBool()
			if isCheck {
				break
			}
		}
	}
	log.Infof("tagrecorder run start")

	go func() {
		for range time.Tick(time.Duration(c.cfg.TagRecorderCfg.Interval) * time.Second) {
			c.run()
		}
	}()
}

func (c *TagRecorder) checkData() {
	domainLcuuidToIconID, resourceTypeToIconID, _ := c.UpdateIconInfo()
	updaters := c.getUpdaters(domainLcuuidToIconID, resourceTypeToIconID)
	for _, updater := range updaters {
		updater.Check()
	}
}

func (t *TagRecorder) Stop() {
	if t.tCancel != nil {
		t.tCancel()
	}
	log.Info("tagrecorder stopped")
}

func (c *TagRecorder) refresh(domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) {
	updaters := c.getUpdaters(domainLcuuidToIconID, resourceTypeToIconID)
	for _, updater := range updaters {
		updater.SetConfig(c.cfg.TagRecorderCfg)
		updater.Refresh()
	}
}

func (c *TagRecorder) getUpdaters(domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) []ChResourceUpdater {
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
		NewChPodService(),
		NewChChost(),
	}
	if c.cfg.RedisCfg.Enabled {
		updaters = append(updaters, NewChIPResource(c.tCtx))
	}

	return updaters
}
