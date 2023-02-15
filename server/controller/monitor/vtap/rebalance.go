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

package vtap

import (
	"context"
	"encoding/json"
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
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
			r.controllerRebalance()
			r.analyzerRebalance()
		}
	}()
}

func (r *RebalanceCheck) Stop() {
	if r.vCancel != nil {
		r.vCancel()
	}
	log.Info("rebalance check stopped")
}

func (r *RebalanceCheck) controllerRebalance() {
	controllers, err := service.GetControllers(map[string]string{})
	if err != nil {
		log.Errorf("get controllers failed, (%v)", err)
		return
	}

	for _, controller := range controllers {
		// check if need rebalance
		if controller.VtapCount == 0 && controller.VTapMax > 0 &&
			controller.State == common.HOST_STATE_COMPLETE && len(controller.Azs) != 0 {
			log.Infof("need rebalance vtap for controller (%s)", controller.IP)
			args := map[string]interface{}{
				"check": false,
				"type":  "controller",
			}
			if result, err := service.VTapRebalance(args); err != nil {
				log.Error(err)
			} else {
				data, _ := json.Marshal(result)
				log.Infof("exec rebalance: %s", string(data))
			}
			break
		}
	}
}

func (r *RebalanceCheck) analyzerRebalance() {
	// check if need rebalance
	analyzers, err := service.GetAnalyzers(map[string]interface{}{})
	if err != nil {
		log.Errorf("get analyzers failed, (%v)", err)
		return
	}

	for _, analyzer := range analyzers {
		if analyzer.VtapCount == 0 && analyzer.VTapMax > 0 &&
			analyzer.State == common.HOST_STATE_COMPLETE && len(analyzer.Azs) != 0 {
			log.Info("need rebalance vtap for analyzer (%s)", analyzer.IP)
			args := map[string]interface{}{
				"check": false,
				"type":  "analyzer",
			}
			if result, err := service.VTapRebalance(args); err != nil {
				log.Error(err)
			} else {
				data, _ := json.Marshal(result)
				log.Infof("exec rebalance: %s", string(data))
			}
			break
		}
	}
}
