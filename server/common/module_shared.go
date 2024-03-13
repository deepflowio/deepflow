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

package common

import (
	"io/ioutil"
	"time"

	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("server_common")

const QUEUE_SIZE = 1 << 16

type ControllerIngesterShared struct {
	ResourceEventQueue *queue.OverwriteQueue
}

func NewControllerIngesterShared() *ControllerIngesterShared {
	return &ControllerIngesterShared{
		ResourceEventQueue: queue.NewOverwriteQueue(
			"controller-to-ingester-resource_event", QUEUE_SIZE,
			queue.OptionFlushIndicator(time.Second*3),
			queue.OptionRelease(func(p interface{}) { p.(*eventapi.ResourceEvent).Release() })),
	}
}

type Config struct {
	Ingester IngesterConfig `yaml:"ingester"`
}

type IngesterConfig struct {
	Exporters []ExportersConfig `yaml:"exporters"`
}

type ExportersConfig struct {
	Enabled bool `yaml:"enabled"`
}

func ExportersEnabled(configPath string) bool {
	configBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Error("Read config file error:", err)
		return false
	}
	config := Config{}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		return false
	}
	for _, v := range config.Ingester.Exporters {
		if v.Enabled {
			log.Info("exporters enabled")
			return true
		}
	}
	return false
}
