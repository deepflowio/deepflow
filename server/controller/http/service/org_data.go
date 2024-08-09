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
	"time"

	"github.com/bitly/go-simplejson"
	servercommon "github.com/deepflowio/deepflow/server/common"
	controllerCommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	mysqlcfg "github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migrator"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/logger"
	"gorm.io/gorm"
)

// CreateORGData create database and backs up the controller and analyzer tables.
// Returns the database name and error.
func CreateORGData(dataCreate model.ORGDataCreate, mysqlCfg mysqlcfg.MySqlConfig) (string, error) {
	log.Infof("create org data", logger.NewORGPrefix(dataCreate.ORGID))
	mysql.CheckORGNumberAndLog()

	defaultDatabase := mysqlCfg.Database
	cfg := common.ReplaceConfigDatabaseName(mysqlCfg, dataCreate.ORGID)
	existed, err := migrator.CreateDatabase(cfg) // TODO use orgID to create db
	if err != nil {
		return cfg.Database, err
	}
	if existed {
		return cfg.Database, errors.New(fmt.Sprintf("database (name: %s) already exists", cfg.Database))
	}

	var controllers []mysql.Controller
	var analyzers []mysql.Analyzer
	if err := mysql.DefaultDB.Unscoped().Find(&controllers).Error; err != nil {
		return defaultDatabase, err
	}
	if err := mysql.DefaultDB.Unscoped().Find(&analyzers).Error; err != nil {
		return defaultDatabase, err
	}

	db, err := mysql.GetDB(dataCreate.ORGID)
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

func DeleteORGData(orgID int, mysqlCfg mysqlcfg.MySqlConfig) (err error) {
	log.Infof("delete org data", logger.NewORGPrefix(orgID))
	cfg := common.ReplaceConfigDatabaseName(mysqlCfg, orgID)
	if err = migrator.DropDatabase(cfg); err != nil {
		return err
	}
	// copy deleted org info to deleted_org table which is used for deleting clickhouse org data asynchronously
	var org *mysql.ORG
	if err = mysql.DefaultDB.Where("org_id = ?", orgID).First(&org).Error; err != nil {
		return err
	}
	deletedORG := &mysql.DeletedORG{
		ORGID:       org.ORGID,
		Name:        org.Name,
		Lcuuid:      org.Lcuuid,
		OwnerUserID: org.OwnerUserID,
	}
	if err = mysql.DefaultDB.Create(deletedORG).Error; err != nil {
		return err
	}
	return nil
}

func DeleteORGDataNonRealTime(orgIDs []int) error {
	var res error
	for _, id := range orgIDs {
		if err := servercommon.DropOrg(uint16(id)); err != nil {
			res = err
		}
	}
	return res
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
		var controller mysql.Controller
		err := mysql.Db.Where("node_type = ? AND state = ?", controllerCommon.CONTROLLER_NODE_TYPE_MASTER, controllerCommon.CONTROLLER_STATE_NORMAL).First(&controller).Error
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

type DeletedORGChecker struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func GetDeletedORGChecker(ctx context.Context) *DeletedORGChecker {
	cCtx, cCancel := context.WithCancel(ctx)
	return &DeletedORGChecker{ctx: cCtx, cancel: cCancel}
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
		ticker := time.NewTicker(time.Duration(5) * time.Minute)
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

	var deletedORGs []*mysql.DeletedORG
	if err := mysql.DefaultDB.Find(&deletedORGs).Error; err != nil {
		log.Errorf("failed to get deleted orgs: %s", err.Error(), mysql.DefaultDB.LogPrefixORGID)
		return
	}
	if len(deletedORGs) == 0 {
		return
	}
	if err := c.triggerAllServersToDelete(deletedORGs); err != nil {
		log.Errorf("failed to trigger all servers to delete orgs: %s", err.Error())
		return
	}
	if err := mysql.DefaultDB.Delete(&deletedORGs).Error; err != nil {
		log.Errorf("failed to delete deleted orgs: %s", err.Error(), mysql.DefaultDB.LogPrefixORGID)
	}
	return
}

func (c *DeletedORGChecker) triggerAllServersToDelete(deletedORGs []*mysql.DeletedORG) error {
	query := ""
	for i, org := range deletedORGs {
		if i == 0 {
			query += fmt.Sprintf("org_id=%d", org.ORGID)
		} else {
			query += fmt.Sprintf("&org_id=%d", org.ORGID)
		}
	}
	var controllers []*mysql.Controller
	if err := mysql.DefaultDB.Find(&controllers).Error; err != nil {
		log.Errorf("failed to get controllers: %s", err.Error(), mysql.DefaultDB.LogPrefixORGID)
		return err
	}
	var res error
	for _, controller := range controllers {
		_, err := controllerCommon.CURLPerform(
			"DELETE",
			fmt.Sprintf("http://%s/v1/org/?%s", net.JoinHostPort(controller.IP, fmt.Sprintf("%d", controllerCommon.GConfig.HTTPNodePort)), query),
			nil,
		)
		if err != nil {
			log.Errorf("failed to call controller %s: %s", controller.IP, err.Error(), mysql.DefaultDB.LogPrefixORGID)
			res = err
		}
	}
	return res
}
