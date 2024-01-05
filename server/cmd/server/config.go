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

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"

	pyroscope "github.com/grafana/pyroscope-go"
	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	LogFile           string            `default:"/var/log/deepflow/server.log" yaml:"log-file"`
	LogLevel          string            `default:"info" yaml:"log-level"`
	ContinuousProfile ContinuousProfile `yaml:"continuous-profile"`
	Profiler          bool              `yaml:"profiler"`
	MaxCPUs           int               `yaml:"max-cpus"`
	MonitorPaths      []string          `yaml:"monitor-paths"`
}

type ContinuousProfile struct {
	Enabled       bool     `yaml:"enabled"`
	ServerAddress string   `yaml:"server-addr"`
	ProfileTypes  []string `yaml:"profile-types"` // pyroscope.ProfileType
	MutexRate     int      `yaml:"mutex-rate"`    // valid when ProfileTypes contains 'mutex_count' or 'mutex_duration'
	BlockRate     int      `yaml:"block-rate"`    // valid when ProfileTypes contains 'block_count' or 'block_duration'
	LogEnabled    bool     `yaml:"log-enabled"`   // logging enabled
}

func loadConfig(path string) *Config {
	config := &Config{
		LogFile:  "/var/log/deepflow/server.log",
		LogLevel: "info",
		ContinuousProfile: ContinuousProfile{
			Enabled:       false,
			ServerAddress: "http://deepflow-agent/api/v1/profile",
			ProfileTypes:  []string{"cpu", "inuse_objects", "alloc_objects", "inuse_space", "alloc_space"},
			MutexRate:     5,
			BlockRate:     5,
			LogEnabled:    true,
		},
		MonitorPaths: []string{"/", "/mnt", "/var/log"},
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("Read config file path: %s, error: %s", err, path)
		os.Exit(1)
	}

	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		fmt.Printf("Unmarshal yaml(%s) error: %s", path, err)
		os.Exit(1)
	}

	return config
}

func startContinuousProfile(config *ContinuousProfile) {
	if !config.Enabled {
		return
	}
	profileTypes := []pyroscope.ProfileType{}
	hasMutexProfile, hasBlockProfile := false, false
	for _, t := range config.ProfileTypes {
		switch pyroscope.ProfileType(t) {
		case pyroscope.ProfileCPU,
			pyroscope.ProfileInuseObjects,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileInuseSpace,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines:
			profileTypes = append(profileTypes, pyroscope.ProfileType(t))
		case pyroscope.ProfileMutexCount, pyroscope.ProfileMutexDuration:
			hasMutexProfile = true
			profileTypes = append(profileTypes, pyroscope.ProfileType(t))
		case pyroscope.ProfileBlockCount, pyroscope.ProfileBlockDuration:
			hasBlockProfile = true
			profileTypes = append(profileTypes, pyroscope.ProfileType(t))
		}
	}

	if hasMutexProfile {
		runtime.SetMutexProfileFraction(config.MutexRate)
	}
	if hasBlockProfile {
		runtime.SetBlockProfileRate(config.BlockRate)
	}
	logger := log
	if !config.LogEnabled {
		logger = nil
	}

	pyroscope.Start(pyroscope.Config{
		ApplicationName: "deepflow-server",
		// replace this with the address of pyroscope server
		ServerAddress: config.ServerAddress,
		// you can disable logging by setting this to nil
		Logger: logger,
		// you can provide static tags via a map:
		Tags:         map[string]string{"hostname": os.Getenv("K8S_NODE_NAME_FOR_DEEPFLOW")},
		ProfileTypes: profileTypes,
	})
}
