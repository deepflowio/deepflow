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

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/bitly/go-simplejson"
	"gorm.io/gorm"

	servercommon "github.com/deepflowio/deepflow/server/common"
	controllerCommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/common"
	metadbcfg "github.com/deepflowio/deepflow/server/controller/db/metadb/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	servicecommon "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db/idmng"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

// CreateORGData create database and backs up the controller and analyzer tables.
// Returns the database name and error.
func CreateORGData(dataCreate model.ORGDataCreate, metadbCfg metadbcfg.Config) (string, error) {
	log.Infof("create org data", logger.NewORGPrefix(dataCreate.ORGID))
	metadb.CheckORGNumberAndLog()

	defaultDatabase := metadbCfg.Database
	cfg := common.ReplaceConfigDatabaseName(metadbCfg, dataCreate.ORGID)
	existed, err := migrator.CreateDatabase(cfg) // TODO use orgID to create db
	if err != nil {
		return cfg.Database, err
	}
	if existed {
		return cfg.Database, errors.New(fmt.Sprintf("database (name: %s) already exists", cfg.Database))
	}

	var controllers []metadbmodel.Controller
	var analyzers []metadbmodel.Analyzer
	if err := metadb.DefaultDB.Unscoped().Find(&controllers).Error; err != nil {
		return defaultDatabase, err
	}
	if err := metadb.DefaultDB.Unscoped().Find(&analyzers).Error; err != nil {
		return defaultDatabase, err
	}

	db, err := metadb.GetDB(dataCreate.ORGID)
	if err != nil {
		return cfg.Database, err
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.CreateInBatches(controllers, len(controllers)).Error; err != nil {
			return err
		}
		return tx.CreateInBatches(analyzers, len(analyzers)).Error
	})
	return cfg.Database, nil
}

func DeleteORGData(orgID int, metadbCfg metadbcfg.Config) (err error) {
	log.Infof("delete org data", logger.NewORGPrefix(orgID))
	cfg := common.ReplaceConfigDatabaseName(metadbCfg, orgID)
	if err = migrator.DropDatabase(cfg); err != nil {
		return err
	}
	return nil
}

func DeleteORGDataNonRealTime(orgIDs []int) error {
	log.Infof("delete orgs (ids: %v) clickhouse data", orgIDs)
	var msg string
	for _, id := range orgIDs {
		if err := servercommon.DropOrg(uint16(id)); err != nil {
			log.Errorf("failed to drop org %d ck: %s", id, err.Error())
			msg += fmt.Sprintf("%s. ", err.Error())
		}
	}
	if msg == "" {
		return nil
	}
	return fmt.Errorf(msg)
}

func GetORGData(cfg *config.ControllerConfig) (*simplejson.Json, error) {
	errResponse, _ := simplejson.NewJson([]byte("{}"))
	// no fpermit
	if !cfg.FPermit.Enabled {
		datas := []map[string]int{}
		orgData := map[string]int{"ORG_ID": controllerCommon.DEFAULT_ORG_ID}
		datas = append(datas, orgData)
		responseBytes, err := json.Marshal(datas)
		if err != nil {
			log.Error(err)
			return errResponse, err
		}
		response, err := simplejson.NewJson(responseBytes)
		if err != nil {
			log.Error(err)
			return errResponse, err
		}
		return response, err
	}

	body := make(map[string]interface{})
	// master region
	if cfg.TrisolarisCfg.NodeType != controllerCommon.TRISOLARIS_NODE_TYPE_MASTER {
		var controller metadbmodel.Controller
		err := metadb.DefaultDB.Where("node_type = ? AND state = ?", controllerCommon.CONTROLLER_NODE_TYPE_MASTER, controllerCommon.CONTROLLER_STATE_NORMAL).First(&controller).Error
		if err != nil {
			log.Error(err)
			return errResponse, err
		}
		orgResponse, err := controllerCommon.CURLPerform("GET", fmt.Sprintf("http://%s:%d/v1/orgs/", controller.IP, cfg.ListenNodePort), body)
		if err != nil {
			log.Error(err)
			return errResponse, err
		}
		response := orgResponse.Get("DATA")
		return response, err
	}
	orgResponse, err := controllerCommon.CURLPerform("GET", fmt.Sprintf("http://%s:%d/v1/orgs", cfg.FPermit.Host, cfg.FPermit.Port), body)
	if err != nil {
		log.Error(err)
		return errResponse, err
	}
	response := orgResponse.Get("DATA")
	return response, err
}

func AllocORGID() (map[string]int, error) {
	ids, err := idmng.GetIDs(controllerCommon.DEFAULT_ORG_ID, controllerCommon.RESOURCE_TYPE_ORG_EN, 1)
	if err != nil {
		log.Errorf("%s request ids failed", controllerCommon.RESOURCE_TYPE_ORG_EN)
		return nil, err
	}
	if len(ids) != 1 {
		log.Errorf("request ids=%v err", ids)
		return nil, servicecommon.NewError(httpcommon.SERVER_ERROR, fmt.Sprintf("request ids=%v err", ids))
	}
	return map[string]int{"ID": ids[0]}, nil
}

var (
	deletedORGCheckerOnce sync.Once
	deleteORGChecker      *DeletedORGChecker
)

type DeletedORGChecker struct {
	ctx    context.Context
	cancel context.CancelFunc

	fpermitCfg controllerCommon.FPermit
}

func GetDeletedORGChecker(ctx context.Context, fpermitCfg controllerCommon.FPermit) *DeletedORGChecker {
	deletedORGCheckerOnce.Do(func() {
		cCtx, cCancel := context.WithCancel(ctx)
		deleteORGChecker = &DeletedORGChecker{ctx: cCtx, cancel: cCancel, fpermitCfg: fpermitCfg}
	})
	return deleteORGChecker
}

func (c *DeletedORGChecker) Start(sCtx context.Context) {
	log.Info("deleted org check started")
	c.checkRegularly(sCtx)
}

func (c *DeletedORGChecker) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	log.Info("deleted org check stopped")
}

func (c *DeletedORGChecker) checkRegularly(sCtx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Duration(1) * time.Minute)
		defer ticker.Stop()
	LOOP:
		for {
			select {
			case <-ticker.C:
				c.check()
			case <-sCtx.Done():
				break LOOP
			case <-c.ctx.Done():
				break LOOP
			}
		}
	}()
}

func (c *DeletedORGChecker) check() {
	log.Infof("check deleted orgs start")
	defer log.Infof("check deleted orgs end")

	deletedORGIDs, err := metadb.GetDeletedORGIDs()
	if err != nil {
		log.Errorf("failed to get deleted orgs: %s", err.Error())
		return
	}
	log.Infof("handle deleted orgs: %v", deletedORGIDs)
	if len(deletedORGIDs) == 0 {
		return
	}
	if err := c.triggerAllServersToDelete(deletedORGIDs); err != nil {
		log.Errorf("failed to trigger all servers to delete orgs: %s", err.Error())
		return
	}
	if err := c.triggerFpermit(deletedORGIDs); err != nil {
		log.Errorf("failed to trigger fpermit to delete orgs: %s", err.Error())
	}
	return
}

func (c *DeletedORGChecker) triggerFpermit(ids []int) error {
	body := map[string]interface{}{
		"org_ids": ids,
	}
	_, err := controllerCommon.CURLPerform(
		http.MethodDelete,
		fmt.Sprintf("http://%s/v1/org", net.JoinHostPort(c.fpermitCfg.Host, fmt.Sprintf("%d", c.fpermitCfg.Port))),
		body,
	)
	return err
}

func (c *DeletedORGChecker) triggerAllServersToDelete(ids []int) error {
	query := ""
	for i, id := range ids {
		if i == 0 {
			query += fmt.Sprintf("org_id=%d", id)
		} else {
			query += fmt.Sprintf("&org_id=%d", id)
		}
	}
	var controllers []*metadbmodel.Controller
	if err := metadb.DefaultDB.Find(&controllers).Error; err != nil {
		log.Errorf("failed to get controllers: %s", err.Error())
		return err
	}
	var res error
	for _, controller := range controllers {
		ip := controller.PodIP
		port := controllerCommon.GConfig.HTTPPort
		if controller.NodeType == controllerCommon.CONTROLLER_NODE_TYPE_SLAVE {
			ip = controller.IP
			port = controllerCommon.GConfig.HTTPNodePort
		}
		_, err := controllerCommon.CURLPerform(
			"DELETE",
			fmt.Sprintf("http://%s/v1/org/?%s", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), query),
			nil,
		)
		if err != nil {
			log.Errorf("failed to call controller %s: %s", controller.Name, err.Error())
			res = err
		}
	}
	return res
}
