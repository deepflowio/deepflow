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

package vtap

import (
	"context"
	"encoding/json"
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/http/service/rebalance"
	"github.com/deepflowio/deepflow/server/controller/monitor/config"
)

type RebalanceCheck struct {
	vCtx    context.Context
	vCancel context.CancelFunc
	cfg     config.MonitorConfig
}

func NewRebalanceCheck(cfg config.MonitorConfig, ctx context.Context) *RebalanceCheck {
	vCtx, vCancel := context.WithCancel(ctx)
	return &RebalanceCheck{
		vCtx:    vCtx,
		vCancel: vCancel,
		cfg:     cfg,
	}
}

func (r *RebalanceCheck) Start() {
	log.Info("rebalance check start")
	go func() {
		if !r.cfg.AutoRebalanceVTap {
			return
		}

		for range time.Tick(time.Duration(r.cfg.RebalanceCheckInterval) * time.Second) {
			for _, db := range mysql.GetDBs().All() {
				r.controllerRebalance(db)
				if r.cfg.IngesterLoadBalancingConfig.Algorithm == common.ANALYZER_ALLOC_BY_AGENT_COUNT {
					r.analyzerRebalance(db)
				}
			}
		}
	}()

	go func() {
		if !r.cfg.AutoRebalanceVTap {
			return
		}

		if r.cfg.IngesterLoadBalancingConfig.Algorithm == common.ANALYZER_ALLOC_BY_INGESTED_DATA {
			duration := r.cfg.IngesterLoadBalancingConfig.DataDuration
			r.analyzerRebalanceByTraffic(duration)
			for range time.Tick(time.Duration(r.cfg.IngesterLoadBalancingConfig.RebalanceInterval) * time.Second) {
				r.analyzerRebalanceByTraffic(duration)
			}
		}
	}()
}

func (r *RebalanceCheck) Stop() {
	if r.vCancel != nil {
		r.vCancel()
	}
	log.Info("rebalance check stopped")
}

func (r *RebalanceCheck) controllerRebalance(db *mysql.DB) {
	controllers, err := service.GetControllers(common.DEFAULT_ORG_ID, map[string]string{})
	if err != nil {
		log.Errorf("ORG(id=%d database=%s) get controllers failed, (%v)", db.ORGID, db.Name, err)
		return
	}

	for _, controller := range controllers {
		// check if need rebalance
		if controller.VtapCount == 0 && controller.VTapMax > 0 &&
			controller.State == common.HOST_STATE_COMPLETE && len(controller.Azs) != 0 {
			log.Infof("ORG(id=%d database=%s) need rebalance vtap for controller (%s)", db.ORGID, db.Name, controller.IP)
			args := map[string]interface{}{
				"check": false,
				"type":  "controller",
			}
			if result, err := service.VTapRebalance(db, args, r.cfg.IngesterLoadBalancingConfig); err != nil {
				log.Errorf("ORG(id=%d database=%s) %s", db.ORGID, db.Name, err.Error())
			} else {
				data, _ := json.Marshal(result)
				log.Infof("ORG(id=%d database=%s) exec rebalance: %s", db.ORGID, db.Name, string(data))
			}
			break
		}
	}
}

func (r *RebalanceCheck) analyzerRebalance(db *mysql.DB) {
	// check if need rebalance
	analyzers, err := service.GetAnalyzers(db.ORGID, map[string]interface{}{})
	if err != nil {
		log.Errorf("ORG(id=%d database=%s) get analyzers failed, (%v)", db.ORGID, db.Name, err)
		return
	}

	for _, analyzer := range analyzers {
		if analyzer.VtapCount == 0 && analyzer.VTapMax > 0 &&
			analyzer.State == common.HOST_STATE_COMPLETE && len(analyzer.Azs) != 0 {
			log.Infof("ORG(id=%d database=%s) need rebalance vtap for analyzer (%s)", db.ORGID, db.Name, analyzer.IP)
			args := map[string]interface{}{
				"check": false,
				"type":  "analyzer",
			}
			if result, err := service.VTapRebalance(db, args, r.cfg.IngesterLoadBalancingConfig); err != nil {
				log.Errorf("ORG(id=%d database=%s) %s", db.ORGID, db.Name, err.Error())
			} else {
				data, _ := json.Marshal(result)
				log.Infof("ORG(id=%d database=%s)exec rebalance: %s", db.ORGID, db.Name, string(data))
			}
			break
		}
	}
}

func (r *RebalanceCheck) analyzerRebalanceByTraffic(dataDuration int) {
	for _, db := range mysql.GetDBs().All() {
		log.Infof("ORG(id=%d database=%s) check analyzer rebalance, traffic duration(%vs)", db.ORGID, db.Name, dataDuration)
		analyzerInfo := rebalance.NewAnalyzerInfo()
		result, err := analyzerInfo.RebalanceAnalyzerByTraffic(db, true, dataDuration)
		if err != nil {
			log.Errorf("ORG(id=%d database=%s) fail to rebalance analyzer by data(if check: true): %v", db.ORGID, db.Name, err)
			return
		}
		if result.TotalSwitchVTapNum != 0 {
			log.Infof("ORG(id=%d database=%s) need rebalance, total switch vtap num(%d)", db.ORGID, db.Name, result.TotalSwitchVTapNum)
			if _, err := analyzerInfo.RebalanceAnalyzerByTraffic(db, false, dataDuration); err != nil {
				log.Errorf("ORG(id=%d database=%s) fail to rebalance analyzer by data(if check: false): %v", db.ORGID, db.Name, err)
			}
			continue
		}
	}
}
