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
	"io/ioutil"
	"reflect"
	"testing"

	yaml "gopkg.in/yaml.v2"
)

type baseConfig struct {
	Config ingesterConfig `yaml:"ingester"`
}

type ingesterConfig struct {
	ExportersCfg []ExporterCfg `yaml:"exporters"`
}

func TestConfig(t *testing.T) {
	ingesterCfg := baseConfig{}
	configBytes, _ := ioutil.ReadFile("./config_test.yaml")
	err := yaml.Unmarshal(configBytes, &ingesterCfg)
	if err != nil {
		t.Fatalf("yaml unmarshal failed: %v", err)
	}
	expect := baseConfig{
		Config: ingesterConfig{
			ExportersCfg: []ExporterCfg{},
		},
	}
	if !reflect.DeepEqual(expect, ingesterCfg) {
		bytes, _ := yaml.Marshal(ingesterCfg)
		t.Logf("yaml unmarshal, got: %s", string(bytes))
	}
}
