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

var cfg *RecorderConfig

type RecorderConfig struct {
	CacheRefreshInterval         uint16 `default:"60" yaml:"cache_refresh_interval"`
	DeletedResourceCleanInterval uint16 `default:"24" yaml:"deleted_resource_clean_interval"`
	DeletedResourceRetentionTime uint16 `default:"168" yaml:"deleted_resource_retention_time"`
	ResourceMaxID0               int    `default:"64000" yaml:"resource_max_id_0"`
	ResourceMaxID1               int    `default:"499999" yaml:"resource_max_id_1"`

	LogDebug LogDebugConfig `yaml:"log_debug"`
}

func Get() *RecorderConfig {
	return cfg
}

func Set(c *RecorderConfig) {
	cfg = c
}

type LogDebugConfig struct {
	Enabled       bool     `default:"false" yaml:"enabled"`
	DetailEnabled bool     `default:"false" yaml:"detail_enabled"`
	ResourceTypes []string `default:"" yaml:"resource_type"`
}
