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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/http/service/rebalance"
	"github.com/deepflowio/deepflow/server/controller/monitor/config"
)

var (
	intervalSendWeight = time.Second * 10
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

func (r *RebalanceCheck) Start(sCtx context.Context) {
	log.Info("rebalance check start")
	go func() {
		if !r.cfg.AutoRebalanceVTap {
			return
		}

		ticker := time.NewTicker(time.Duration(r.cfg.RebalanceCheckInterval) * time.Second)
		defer ticker.Stop()
	LOOP1:
		for {
			select {
			case <-ticker.C:
				for _, db := range metadb.GetDBs().All() {
					r.controllerRebalance(db)
					if r.cfg.IngesterLoadBalancingConfig.Algorithm == common.ANALYZER_ALLOC_BY_AGENT_COUNT {
						r.analyzerRebalance(db)
					}
				}
			case <-sCtx.Done():
				break LOOP1
			case <-r.vCtx.Done():
				break LOOP1
			}
		}
	}()

	go func() {
		if !r.cfg.AutoRebalanceVTap {
			return
		}

		if r.cfg.IngesterLoadBalancingConfig.Algorithm != common.ANALYZER_ALLOC_BY_INGESTED_DATA {
			return
		}

		duration := r.cfg.IngesterLoadBalancingConfig.DataDuration
		r.analyzerRebalanceByTraffic(duration)

		// report agent weight every 10 secends
		sendWeight(sCtx, duration)

		ticker := time.NewTicker(time.Duration(r.cfg.IngesterLoadBalancingConfig.RebalanceInterval) * time.Second)
		defer ticker.Stop()
	LOOP2:
		for {
			select {
			case <-ticker.C:
				r.analyzerRebalanceByTraffic(duration)
			case <-sCtx.Done():
				break LOOP2
			case <-r.vCtx.Done():
				break LOOP2
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

func (r *RebalanceCheck) controllerRebalance(db *metadb.DB) {
	controllers, err := service.GetControllers(common.DEFAULT_ORG_ID, map[string]string{})
	if err != nil {
		log.Errorf("get controllers failed, (%v)", err, db.LogPrefixORGID)
		return
	}

	for _, controller := range controllers {
		// check if need rebalance
		if controller.VtapCount == 0 && controller.VTapMax > 0 &&
			controller.State == common.HOST_STATE_COMPLETE && len(controller.Azs) != 0 {
			log.Infof("need rebalance vtap for controller (%s)", controller.IP, db.LogPrefixORGID)
			args := map[string]interface{}{
				"check": false,
				"type":  "controller",
			}
			if result, err := service.VTapRebalance(db, args, r.cfg.IngesterLoadBalancingConfig); err != nil {
				log.Errorf("%s", err.Error(), db.LogPrefixORGID)
			} else {
				data, _ := json.Marshal(result)
				log.Infof("exec rebalance: %s", string(data), db.LogPrefixORGID)
			}
			break
		}
	}
}

func (r *RebalanceCheck) analyzerRebalance(db *metadb.DB) {
	// check if need rebalance
	analyzers, err := service.GetAnalyzers(db.ORGID, map[string]interface{}{})
	if err != nil {
		log.Errorf("get analyzers failed, (%v)", err, db.LogPrefixORGID)
		return
	}

	for _, analyzer := range analyzers {
		if analyzer.VtapCount == 0 && analyzer.VTapMax > 0 &&
			analyzer.State == common.HOST_STATE_COMPLETE && len(analyzer.Azs) != 0 {
			log.Infof("need rebalance vtap for analyzer (%s)", analyzer.IP, db.LogPrefixORGID)
			args := map[string]interface{}{
				"check": false,
				"type":  "analyzer",
			}
			if result, err := service.VTapRebalance(db, args, r.cfg.IngesterLoadBalancingConfig); err != nil {
				log.Errorf("%s", err.Error(), db.LogPrefixORGID)
			} else {
				data, _ := json.Marshal(result)
				log.Infof("exec rebalance: %s", string(data), db.LogPrefixORGID)
			}
			break
		}
	}
}

func (r *RebalanceCheck) analyzerRebalanceByTraffic(dataDuration int) {
	for _, db := range metadb.GetDBs().All() {
		log.Infof("check analyzer rebalance, traffic duration(%vs)", dataDuration, db.LogPrefixORGID)
		analyzerInfo := rebalance.NewAnalyzerInfo(false)
		result, err := analyzerInfo.RebalanceAnalyzerByTraffic(db, true, dataDuration)
		if err != nil {
			log.Errorf("fail to rebalance analyzer by data(if check: true): %v", err, db.LogPrefixORGID)
			return
		}
		if result != nil && result.TotalSwitchVTapNum != 0 {
			log.Infof("need rebalance, total switch vtap num(%d)", result.TotalSwitchVTapNum, db.LogPrefixORGID)
			if _, err := analyzerInfo.RebalanceAnalyzerByTraffic(db, false, dataDuration); err != nil {
				log.Errorf("fail to rebalance analyzer by data(if check: false): %v", err, db.LogPrefixORGID)
			}
			continue
		}
	}
}

func sendWeight(ctx context.Context, dataDuration int) {
	go func() {
		ticker := time.NewTicker(intervalSendWeight)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Infof("agent traffic context done")
				return
			case <-ticker.C:
				for _, db := range metadb.GetDBs().All() {
					analyzerInfo := rebalance.NewAnalyzerInfo(true)
					_, err := analyzerInfo.RebalanceAnalyzerByTraffic(db, true, dataDuration)
					if err != nil {
						log.Errorf("fail to rebalance analyzer by data(if check: true): %v", err, db.LogPrefixORGID)
						return
					}
				}
			}
		}
	}()
}
