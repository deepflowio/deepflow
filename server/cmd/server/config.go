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
	"os"
	"runtime"
	"strings"

	pyroscope "github.com/grafana/pyroscope-go"
	yaml "gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/debug"
)

type Config struct {
	LogFile             string              `default:"/var/log/deepflow/server.log" yaml:"log-file"`
	LogLevel            string              `default:"info" yaml:"log-level"`
	ContinuousProfile   ContinuousProfile   `yaml:"continuous-profile"`
	Profiler            bool                `yaml:"profiler"`
	MaxCPUs             int                 `yaml:"max-cpus"`
	MonitorPaths        []string            `yaml:"monitor-paths"`
	FreeOSMemoryManager FreeOSMemoryManager `yaml:"free-os-memory-manager"`
}

type FreeOSMemoryManager struct {
	Enabled  bool `yaml:"enabled"`
	Interval int  `yaml:"interval"`
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
		MonitorPaths:        []string{"/", "/mnt", "/var/log"},
		FreeOSMemoryManager: FreeOSMemoryManager{false, DEFAULT_FREE_INTERVAL_SECOND},
	}
	configBytes, err := os.ReadFile(path)
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

type ContinuousProfiler struct {
	cfg      *ContinuousProfile
	profiler *pyroscope.Profiler
	running  bool

	profileTypes  []string
	serverAddress string
}

func NewContinuousProfiler(config *ContinuousProfile) *ContinuousProfiler {
	p := &ContinuousProfiler{
		cfg:           config,
		profileTypes:  config.ProfileTypes,
		serverAddress: config.ServerAddress,
	}
	debug.ServerRegisterSimple(ingesterctl.CMD_CONTINUOUS_PROFILER, p)
	return p
}

func logInfo(str string) string {
	log.Info(str)
	return str
}

const (
	CMD_OPERRATE_ON uint16 = iota
	CMD_OPERRATE_OFF
	CMD_OPERATE_STATUS
	CMD_OPERATE_SET_SERVER_ADDR
	CMD_OPERATE_SET_PROFILE_TYPES
)

func (p *ContinuousProfiler) HandleSimpleCommand(op uint16, arg string) string {
	switch op {
	case CMD_OPERRATE_ON:
		if p.running {
			return logInfo("continuous profile already running")
		}
		err := p.Start(true)
		if err != nil {
			return logInfo(fmt.Sprintf("continuous profile staring failed: %s ", err))
		}
		p.running = true
		return logInfo("continuous profile starting success")
	case CMD_OPERRATE_OFF:
		if p.running && p.profiler != nil {
			p.profiler.Stop()
		} else {
			return logInfo("continuous profile already stopped")
		}
		p.profiler = nil
		p.running = false
		return logInfo("continuous profile stop success")
	case CMD_OPERATE_STATUS:
		if p.running {
			return logInfo(fmt.Sprintf("continuous profile is running\nserver-addr: %s\nprofile-types: %s", p.serverAddress, strings.Join(p.profileTypes, ",")))
		} else {
			return logInfo(fmt.Sprintf("continuous profile is stopped\nserver-addr: %s\nprofile-types: %s", p.serverAddress, strings.Join(p.profileTypes, ",")))
		}
	case CMD_OPERATE_SET_SERVER_ADDR:
		if len(arg) > 0 {
			oldServerAddress := p.serverAddress
			p.serverAddress = arg
			return logInfo(fmt.Sprintf("set continuous profile server addr from %s to %s. need to restart continuous profiler to take effect", oldServerAddress, arg))
		}
		return logInfo("continuous profile should not set server addr empty")
	case CMD_OPERATE_SET_PROFILE_TYPES:
		if len(arg) > 0 {
			oldProfileTypes := p.profileTypes
			p.profileTypes = strings.Split(arg, ",")
			return logInfo(fmt.Sprintf("set continuous profile types from %s to %s. need to restart continuous profiler to take effect", strings.Join(oldProfileTypes, ","), strings.Join(p.profileTypes, ",")))
		} else {
			return logInfo("continuous profile should not set profile types empty")
		}
	}
	return logInfo("invalid arg, should be 'on', 'off', 'status', 'set-server-type', 'set-profile-types'")
}

func (p *ContinuousProfiler) Start(forced bool) error {
	config := p.cfg
	if !config.Enabled && !forced {
		return nil
	}
	if p.running {
		return fmt.Errorf("already runing")
	}

	profileTypes := []pyroscope.ProfileType{}
	hasMutexProfile, hasBlockProfile := false, false

	for _, t := range p.profileTypes {
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
		default:
			log.Warningf("invalid profile type: %s", t)
		}
	}
	log.Info("continuous profile profile types: %v", profileTypes)

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
	var err error
	p.profiler, err = pyroscope.Start(pyroscope.Config{
		ApplicationName: "deepflow-server",
		// replace this with the address of pyroscope server
		ServerAddress: p.serverAddress,
		// you can disable logging by setting this to nil
		Logger: logger,
		// you can provide static tags via a map:
		Tags:         map[string]string{"hostname": os.Getenv("K8S_NODE_NAME_FOR_DEEPFLOW")},
		ProfileTypes: profileTypes,
	})
	if err != nil {
		log.Warningf("start continuous profiler failed: %s", err)
	} else {
		p.running = true
		log.Info("start continuous profiler")
	}
	return err
}
