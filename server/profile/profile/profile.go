/*
 * Copyright (c) 2022 Yunshan Networks
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

package profile

import (
	"fmt"
	"io"
	"os"

	"github.com/gin-gonic/gin"
	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/profile/config"
	"github.com/deepflowio/deepflow/server/profile/router"
)

var log = logging.MustGetLogger("profile")

func Start(configPath, serverLogFile string) {
	ServerCfg := config.DefaultConfig()
	ServerCfg.Load(configPath)
	config.Cfg = &ServerCfg.ProfileConfig
	cfg := ServerCfg.ProfileConfig
	bytes, _ := yaml.Marshal(cfg)
	log.Info("==================== Launching DeepFlow-Server-Profile ====================")
	log.Infof("profile config:\n%s", string(bytes))

	ginLogFile, _ := os.OpenFile(serverLogFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	gin.DefaultWriter = io.MultiWriter(ginLogFile, os.Stdout)

	// 注册router
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.LoggerWithFormatter(logger.GinLogFormat))
	router.ProfileRouter(r)
	// TODO: 增加router
	if err := r.Run(fmt.Sprintf(":%d", cfg.ListenPort)); err != nil {
		log.Errorf("startup service failed, err:%v\n", err)
		os.Exit(0)
	}
}
