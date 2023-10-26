/*
 * Copyright (c) 2023 Yunshan Networks
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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/deepflowio/deepflow/server/common"
	"github.com/deepflowio/deepflow/server/controller/controller"
	"github.com/deepflowio/deepflow/server/controller/report"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/ingester/ingester"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/querier/querier"
	pyroscope "github.com/grafana/pyroscope-go"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

func execName() string {
	splitted := strings.Split(os.Args[0], "/")
	return splitted[len(splitted)-1]
}

var log = logging.MustGetLogger(execName())

var flagSet = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
var configPath = flagSet.String("f", "/etc/server.yaml", "Specify config file location")
var version = flagSet.Bool("v", false, "Display the version")

var Branch, RevCount, Revision, CommitDate, goVersion, CompileTime string

type Config struct {
	LogFile           string            `default:"/var/log/deepflow/server.log" yaml:"log-file"`
	LogLevel          string            `default:"info" yaml:"log-level"`
	ContinuousProfile ContinuousProfile `yaml:"continuous-profile"`
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

func main() {
	flagSet.Parse(os.Args[1:])
	if *version {
		fmt.Printf(
			"%s\n%s\n%s\n%s\n%s\n%s\n",
			"Name: deepflow-server community edition",
			"Branch: "+Branch,
			"CommitID: "+Revision,
			"RevCount: "+RevCount,
			"Compiler: "+goVersion,
			"CompileTime: "+CompileTime,
		)
		os.Exit(0)
	}

	cfg := loadConfig(*configPath)
	logger.EnableStdoutLog()
	logger.EnableFileLog(cfg.LogFile)
	logLevel, _ := logging.LogLevel(cfg.LogLevel)
	logging.SetLevel(logLevel, "")

	log.Infof("deepflow-server config: %+v", *cfg)
	startContinuousProfile(&cfg.ContinuousProfile)

	ctx, cancel := utils.NewWaitGroupCtx()
	defer func() {
		cancel()
		utils.GetWaitGroupInCtx(ctx).Wait() // wait for goroutine cancel
	}()

	report.SetServerInfo(Branch, RevCount, Revision)

	shared := common.NewControllerIngesterShared()

	go controller.Start(ctx, *configPath, cfg.LogFile, shared)

	go querier.Start(*configPath, cfg.LogFile)
	closers := ingester.Start(*configPath, shared)

	common.NewMonitor()

	// TODO: loghandle提取出来，并增加log
	// setup system signal
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	wg := sync.WaitGroup{}
	wg.Add(len(closers))
	for _, closer := range closers {
		go func(c io.Closer) {
			c.Close()
			wg.Done()
		}(closer)
	}
	wg.Wait()
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
