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
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/op/go-logging"
	"gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("tracemap")
var Cfg *TraceMapConfig

type Config struct {
	TraceMapConfig TraceMapConfig `yaml:"trace-map"`
}

type TraceMapConfig struct {
	MaxTracePerIteration      uint64  `default:"100000" yaml:"max_trace_per_iteration"`
	BatchTracesCountMax       uint64  `default:"1000" yaml:"batch_traces_count_max"`
	TraceIdQueryIterations    uint64  `default:"8" yaml:"trace_id_query_iterations"`
	TraceQueryDelta           uint64  `default:"300" yaml:"trace_query_delta"`
	TraceTreeCacheDelay       uint32  `default:"120" yaml:"trace_tree_cache_delay"`
	WriteInterval             int     `default:"60" yaml:"write_interval"`
	WriteBatchSize            int     `default:"1000" yaml:"write_batch_size"`
	Querier                   Querier `yaml:"querier"`
	DebugSqlLenMax            int     `default:"1000" yaml:"debug_sql_len_max"`
	MultiTraceIdMaxIterations int     `default:"30" yaml:"multi_trace_id_max_iterations"`
}

type Querier struct {
	Host string `default:"127.0.0.1" yaml:"host"`
	Port int    `default:"20416" yaml:"port"`
}

func (c *Config) expendEnv() {
	reConfig := reflect.ValueOf(&c.TraceMapConfig)
	reConfig = reConfig.Elem()
	for i := 0; i < reConfig.NumField(); i++ {
		field := reConfig.Field(i)
		switch field.Type().String() {
		case "string":
			fieldStr := field.String()
			pattern := regexp.MustCompile(`\$\{(.+?)\}`)
			p := pattern.FindAllSubmatch([]byte(fieldStr), -1)
			for _, i := range p {
				str := string(i[1])
				fieldStr = strings.Replace(fieldStr, string(i[0]), os.Getenv(str), 1)
			}
			field.SetString(fieldStr)
		}
	}
}

func (c *Config) Validate() error {
	return nil
}

func (c *Config) Load(path string) {
	configBytes, err := os.ReadFile(path)
	if err != nil {
		log.Error("Read config file error:", err, path)
		os.Exit(1)
	}

	if err = yaml.Unmarshal(configBytes, c); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = c.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	c.expendEnv()
}

func DefaultConfig() *Config {
	cfg := &Config{}
	if err := SetDefault(cfg); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return cfg
}
