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

package config

import (
	cloudconfig "github.com/deepflowio/deepflow/server/controller/cloud/config"
	recorderconfig "github.com/deepflowio/deepflow/server/controller/recorder/config"
)

type TaskConfig struct {
	ResourceRecorderInterval uint32                        `default:"60" yaml:"resource_recorder_interval"`
	CloudCfg                 cloudconfig.CloudConfig       `yaml:"cloud"`
	RecorderCfg              recorderconfig.RecorderConfig `yaml:"recorder"`
}

type ManagerConfig struct {
	CloudConfigCheckInterval uint32     `default:"60" yaml:"cloud_config_check_interval"`
	TaskCfg                  TaskConfig `yaml:"task"`
}
