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

package encoder

import (
	"sync"

	"github.com/op/go-logging"
	"golang.org/x/sync/errgroup"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/tagingestrant/prometheus/common"
	prometheuscfg "github.com/deepflowio/deepflow/server/controller/tagingestrant/prometheus/config"
)

var log = logging.MustGetLogger("prometheus.synchronizer.encoder")

type Encoder struct {
	org *common.ORG
	mux sync.Mutex

	metricName  *metricName
	labelName   *labelName
	labelValue  *labelValue
	LabelLayout *labelLayout
	label       *label
}

func newEncoder(cfg prometheuscfg.Config, orgID int) (*Encoder, error) {
	log.Infof("[OID-%d] new prometheus encoder", orgID)
	org, err := common.NewORG(orgID)
	if err != nil {
		log.Errorf("[OID-%d] failed to create org object: %s", orgID, err.Error())
		return nil, err
	}
	e := &Encoder{org: org}
	e.metricName = newMetricName(org, cfg.ResourceMaxID1)
	e.labelName = newLabelName(org, cfg.ResourceMaxID0)
	e.labelValue = newLabelValue(org)
	e.label = newLabel(org)
	e.LabelLayout = newLabelLayout(org, cfg)
	return e, nil
}

func (e *Encoder) Refresh() error {
	e.mux.Lock()
	defer e.mux.Unlock()

	log.Info(e.org.Log("prometheus encoder refresh started"))
	e.label.refresh()
	eg := &errgroup.Group{}
	common.AppendErrGroup(eg, e.metricName.refresh)
	common.AppendErrGroup(eg, e.labelName.refresh)
	common.AppendErrGroup(eg, e.labelValue.refresh)
	common.AppendErrGroup(eg, e.LabelLayout.refresh)
	err := eg.Wait()
	log.Info(e.org.Log("prometheus encoder refresh completed"))
	return err
}

func (e *Encoder) Encode(req *controller.SyncPrometheusRequest) (*controller.SyncPrometheusResponse, error) {
	resp := new(controller.SyncPrometheusResponse)
	eg1RunAhead := &errgroup.Group{}
	common.AppendErrGroup(eg1RunAhead, e.encodeMetricName, resp, req.GetMetricNames())
	common.AppendErrGroup(eg1RunAhead, e.encodeLabelName, resp, req.GetLabelNames())
	common.AppendErrGroup(eg1RunAhead, e.encodeLabelValue, resp, req.GetLabelValues())
	err := eg1RunAhead.Wait()
	if err != nil {
		return resp, err
	}
	eg2RunAhead := &errgroup.Group{}
	common.AppendErrGroup(eg2RunAhead, e.encodeLabel, resp, req.GetLabels())
	common.AppendErrGroup(eg2RunAhead, e.encodeLabelIndex, resp, req.GetMetricAppLabelLayouts())
	err = eg2RunAhead.Wait()
	return resp, err
}

func (e *Encoder) encodeMetricName(args ...interface{}) error {
	resp := args[0].(*controller.SyncPrometheusResponse)
	names := args[1].([]string)
	mns, err := e.metricName.encode(names)
	if err != nil {
		return err
	}
	resp.MetricNames = mns
	return nil
}

func (e *Encoder) encodeLabelName(args ...interface{}) error {
	resp := args[0].(*controller.SyncPrometheusResponse)
	names := args[1].([]string)
	lns, err := e.labelName.encode(names)
	if err != nil {
		return err
	}
	resp.LabelNames = lns
	return nil
}

func (e *Encoder) encodeLabelValue(args ...interface{}) error {
	resp := args[0].(*controller.SyncPrometheusResponse)
	values := args[1].([]string)
	lvs, err := e.labelValue.encode(values)
	if err != nil {
		return err
	}
	resp.LabelValues = lvs
	return nil
}

func (e *Encoder) encodeLabelIndex(args ...interface{}) error {
	resp := args[0].(*controller.SyncPrometheusResponse)
	layouts := args[1].([]*controller.PrometheusMetricAPPLabelLayoutRequest)
	lis, err := e.LabelLayout.encode(layouts)
	if err != nil {
		return err
	}
	resp.MetricAppLabelLayouts = lis
	return nil
}

func (e *Encoder) encodeLabel(args ...interface{}) error {
	resp := args[0].(*controller.SyncPrometheusResponse)
	labels := args[1].([]*controller.PrometheusLabelRequest)
	ls, err := e.label.encode(labels)
	if err != nil {
		return err
	}
	resp.Labels = ls
	return nil
}
