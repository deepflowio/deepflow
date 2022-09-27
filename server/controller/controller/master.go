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

package controller

import (
	"os"
	"time"

	"github.com/deepflowys/deepflow/server/controller/config"
	"github.com/deepflowys/deepflow/server/controller/db/mysql/migrator"
	"github.com/deepflowys/deepflow/server/controller/election"
	recorderdb "github.com/deepflowys/deepflow/server/controller/recorder/db"
)

func IsMasterRegion(cfg *config.ControllerConfig) bool {
	if cfg.TrisolarisCfg.NodeType == "master" {
		return true
	}
	return false
}

// try to check until success
func IsMasterController(cfg *config.ControllerConfig) bool {
	if IsMasterRegion(cfg) {
		for range time.Tick(time.Second * 5) {
			isMasterController, err := election.IsMasterController()
			if err == nil {
				if isMasterController {
					return true
				} else {
					return false
				}
			} else {
				log.Error("check whether it is master controller failed: %s", err.Error())
			}
		}
	}
	return false
}

// migrate db by master region master controller
func migrateDB(cfg *config.ControllerConfig) {
	ok := migrator.MigrateMySQL(cfg.MySqlCfg)
	if !ok {
		log.Error("migrate mysql failed")
		time.Sleep(time.Second)
		os.Exit(0)
	}
}

// start ID manager in master region master controller
func startResourceIDManager(cfg *config.ControllerConfig) {
	if recorderdb.IDMNG != nil {
		return
	}
	err := recorderdb.InitIDManager(&cfg.ManagerCfg.TaskCfg.RecorderCfg)
	if err != nil {
		log.Error("start resource id mananger failed")
		time.Sleep(time.Second)
		os.Exit(0)
	}
}
