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
	"sync"

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
		tagRecorder = &TagRecorder{
			Dictionary:        GetDictionary(),
			UpdaterManager:    GetUpdaterManager(),
			SubscriberManager: GetSubscriberManager(),
		}
	})
	return tagRecorder
}

type TagRecorder struct {
	Dictionary        *Dictionary        // run in master controller of all regions
	UpdaterManager    *UpdaterManager    // run in master controller of master region
	SubscriberManager *SubscriberManager // run in all controllers of all regions
}

func (c *TagRecorder) Init(ctx context.Context, cfg config.ControllerConfig) {
	c.Dictionary.Init(cfg)
	c.UpdaterManager.Init(ctx, cfg)
	c.SubscriberManager.Init(cfg.TagRecorderCfg)
}

var (
	updaterManagerOnce sync.Once
	updaterManager     *UpdaterManager
)
