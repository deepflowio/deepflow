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

package datasource

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/gorilla/mux"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("data_source")

const (
	MAX_DATASOURCE_COUNT = 64
)

type DatasourceManager struct {
	ckAddrs          *[]string // 需要修改数据源的clickhouse地址, 支持多个
	currentCkAddrs   []string
	user             string
	password         string
	readTimeout      int
	replicaEnabled   bool
	ckdbColdStorages map[string]*ckdb.ColdStorage
	isModifyingFlags [ckdb.MAX_ORG_ID + 1][MAX_DATASOURCE_COUNT]bool
	cks              common.DBs

	ckdbCluster       string
	ckdbStoragePolicy string
	ckdbType          string

	server *http.Server
}

func NewDatasourceManager(cfg *config.Config, readTimeout int) *DatasourceManager {
	m := &DatasourceManager{
		ckAddrs:           cfg.CKDB.ActualAddrs,
		currentCkAddrs:    utils.CloneStringSlice(*cfg.CKDB.ActualAddrs),
		user:              cfg.CKDBAuth.Username,
		password:          cfg.CKDBAuth.Password,
		readTimeout:       readTimeout,
		ckdbCluster:       cfg.CKDB.ClusterName,
		ckdbStoragePolicy: cfg.CKDB.StoragePolicy,
		ckdbType:          cfg.CKDB.Type,
		ckdbColdStorages:  cfg.GetCKDBColdStorages(),
		server: &http.Server{
			Addr:    ":" + strconv.Itoa(int(cfg.DatasourceListenPort)),
			Handler: mux.NewRouter(),
		},
	}
	cks, err := common.NewCKConnections(m.currentCkAddrs, m.user, m.password)
	if err != nil {
		log.Fatalf("create clickhouse connections failed: %s", err)
	}
	m.cks = cks
	return m
}

type JsonResp struct {
	OptStatus   string `json:"OPT_STATUS"`
	Description string `json:"DESCRIPTION,omitempty"`
}

func respSuccess(w http.ResponseWriter) {
	resp, _ := json.Marshal(JsonResp{
		OptStatus: "SUCCESS",
	})
	w.Write(resp)
	log.Info("resp success")
}

func respFailed(w http.ResponseWriter, desc string) {
	resp, _ := json.Marshal(JsonResp{
		OptStatus:   "FAILED",
		Description: desc,
	})
	w.Write(resp)
	log.Warningf("resp failed: %s", desc)
}

func respPending(w http.ResponseWriter, desc string) {
	resp, _ := json.Marshal(JsonResp{
		OptStatus:   "PENDING",
		Description: desc,
	})
	w.Write(resp)
	log.Infof("resp pending: %s", desc)
}

type AddBody struct {
	OrgID        int    `json:"org-id"`
	BaseRP       string `json:"base-rp"`
	DB           string `json:"db"`
	Interval     int    `json:"interval"`
	Name         string `json:"name"`
	Duration     int    `json:"retention-time"`
	SummableOP   string `json:"summable-metrics-op"`
	UnsummableOP string `json:"unsummable-metrics-op"`
}

type ModBody struct {
	OrgID    int    `json:"org-id"`
	DB       string `json:"db"`
	Name     string `json:"name"`
	Duration int    `json:"retention-time"`
}

type DelBody struct {
	OrgID int    `json:"org-id"`
	DB    string `json:"db"`
	Name  string `json:"name"`
}

func (m *DatasourceManager) rpAdd(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("read body err, %v", err)
		respFailed(w, err.Error())
		return
	}
	var b AddBody
	if err = json.Unmarshal(body, &b); err != nil {
		log.Errorf("Unmarshal err, %v", err)
		respFailed(w, err.Error())
		return
	}
	log.Infof("receive rpadd request: %+v", b)

	err = m.Handle(b.OrgID, ADD, b.DB, b.BaseRP, b.Name, b.SummableOP, b.UnsummableOP, b.Interval, b.Duration)
	if err != nil {
		respFailed(w, err.Error())
		return
	}
	respSuccess(w)
}

func (m *DatasourceManager) rpMod(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("read body err, %v", err)
		respFailed(w, err.Error())
		return
	}
	var b ModBody
	if err = json.Unmarshal(body, &b); err != nil {
		log.Errorf("Unmarshal err, %v", err)
		respFailed(w, err.Error())
		return
	}
	log.Infof("receive rpmod request: %+v", b)

	err = m.Handle(b.OrgID, MOD, b.DB, "", b.Name, "", "", 0, b.Duration)
	if err != nil {
		if strings.Contains(err.Error(), "try again") {
			respPending(w, err.Error())
		} else {
			respFailed(w, err.Error())
		}
		return
	}

	respSuccess(w)
}

func (m *DatasourceManager) rpDel(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("read body err, %v", err)
		respFailed(w, err.Error())
		return
	}
	var b ModBody
	if err = json.Unmarshal(body, &b); err != nil {
		log.Errorf("Unmarshal err, %v", err)
		respFailed(w, err.Error())
		return
	}
	log.Infof("receive rpdel request: %+v", b)

	err = m.Handle(b.OrgID, DEL, b.DB, "", b.Name, "", "", 0, 0)
	if err != nil {
		respFailed(w, err.Error())
		return
	}
	respSuccess(w)
}

func (m *DatasourceManager) RegisterHandlers() {
	router := m.server.Handler.(*mux.Router)
	router.HandleFunc("/v1/rpadd/", m.rpAdd).Methods("POST")
	router.HandleFunc("/v1/rpmod/", m.rpMod).Methods("PATCH")
	router.HandleFunc("/v1/rpdel/", m.rpDel).Methods("DELETE")
}

func (m *DatasourceManager) Start() {
	m.RegisterHandlers()

	go func() {
		if err := m.server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe() failed: %v", err)
		}
	}()
	log.Info("data_source manager started")
}

func (m *DatasourceManager) Close() error {
	if m.server == nil {
		return nil
	}
	m.cks.Close()
	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)

	err := m.server.Shutdown(ctx)
	if err != nil {
		log.Warningf("shutdown failed: %v", err)
	} else {
		log.Info("data_source manager stopped")
	}
	cancel()

	return err
}
