/**
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

type Config struct {
	SynchronizerCacheRefreshInterval int `default:"60" yaml:"synchronizer_cache_refresh_interval"`
	EncoderCacheRefreshInterval      int `default:"3600" yaml:"encoder_cache_refresh_interval"`
	ResourceMaxID0                   int `default:"64000" yaml:"resource_max_id_0"`
	ResourceMaxID1                   int `default:"499999" yaml:"resource_max_id_1"`
	APPLabelIndexMax                 int `default:"255" yaml:"app_label_index"`
	DataCleanInterval                int `default:"1440" yaml:"data_clean_interval"`
}
