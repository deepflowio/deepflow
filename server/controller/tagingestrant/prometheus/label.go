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

package prometheus

import (
	"sync/atomic"

	mapset "github.com/deckarep/golang-set/v2"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/grpc/statsd"
	"github.com/deepflowio/deepflow/server/controller/tagingestrant/prometheus/cache"
	"github.com/deepflowio/deepflow/server/controller/tagingestrant/prometheus/common"
)

func newLabelResponse(version uint32) *trident.PrometheusLabelResponse {
	return &trident.PrometheusLabelResponse{Version: &version}
}

type ORGLabelSynchronizers struct {
	statsdCounter *statsd.PrometheusLabelIDsCounter
}

func (s *ORGLabelSynchronizers) GetStatsdCounter() *statsd.PrometheusLabelIDsCounter {
	return s.statsdCounter
}

func NewORGLabelSynchronizer() (*ORGLabelSynchronizers, error) {
	return &ORGLabelSynchronizers{
		statsdCounter: statsd.NewPrometheusLabelIDsCounter(),
	}, nil
}

func (s *ORGLabelSynchronizers) Sync(req *trident.PrometheusLabelRequest) (*trident.PrometheusLabelResponse, error) {
	if req == nil {
		log.Warning("empty request")
		return &trident.PrometheusLabelResponse{}, nil
	}
	if len(req.GetRequestLabels()) == 0 {
		curVersion := GetVersion().Get()
		if req.GetVersion() == curVersion {
			log.Infof("label version is up to date: %d", curVersion)
			return newLabelResponse(curVersion), nil
		}
		log.Infof("label version update from %d to %d", req.GetVersion(), curVersion)
		return s.assembleFully(curVersion)
	}
	return s.assemble(req)
}

func (s *ORGLabelSynchronizers) assembleFully(version uint32) (*trident.PrometheusLabelResponse, error) {
	orgIDToResp := cmap.NewWithCustomShardingFunction[int, *trident.PrometheusLabelResponse](common.ShardingInt)
	eg := &errgroup.Group{}
	for iter := range cache.GetORGCaches().GetORGIDToCache().IterBuffered() {
		common.AppendErrGroup(eg, s.goAssembleFully, orgIDToResp, iter.Val)
	}
	if err := eg.Wait(); err != nil {
		return nil, errors.Wrap(err, "assembleFully")
	}
	// merge all orgs' response
	resp := newLabelResponse(version)
	for iter := range orgIDToResp.IterBuffered() {
		resp.ResponseLabelIds = append(resp.ResponseLabelIds, iter.Val.ResponseLabelIds...)
		resp.OrgResponseLabels = append(resp.OrgResponseLabels, iter.Val.OrgResponseLabels...)
	}
	return resp, nil
}

func (s *ORGLabelSynchronizers) goAssembleFully(args ...interface{}) error {
	orgIDToResp := args[0].(cmap.ConcurrentMap[int, *trident.PrometheusLabelResponse])
	cache := args[1].(*cache.Cache)
	synchronizer := newLabelSynchronizer(cache)
	resp, err := synchronizer.assembleFully()
	if err != nil {
		return errors.Wrap(err, "goAssembleFully")
	}
	orgIDToResp.Set(synchronizer.org.GetID(), resp)
	s.appendStatsdCounter(synchronizer)
	return nil
}

func (s *ORGLabelSynchronizers) assemble(req *trident.PrometheusLabelRequest) (*trident.PrometheusLabelResponse, error) {
	orgIDToReqLabels := make(map[int][]*trident.MetricLabelRequest)
	for _, r := range req.GetRequestLabels() {
		orgIDToReqLabels[int(r.GetOrgId())] = append(orgIDToReqLabels[int(r.GetOrgId())], r)
	}
	orgIDToResp := cmap.NewWithCustomShardingFunction[int, *trident.PrometheusLabelResponse](common.ShardingInt)
	eg := &errgroup.Group{}
	for orgID, reqLabels := range orgIDToReqLabels {
		common.AppendErrGroup(eg, s.goAssemble, orgIDToResp, orgID, reqLabels)
	}
	if err := eg.Wait(); err != nil {
		return nil, errors.Wrap(err, "assemble")
	}
	resp := &trident.PrometheusLabelResponse{}
	for iter := range orgIDToResp.IterBuffered() {
		resp.ResponseLabelIds = append(resp.ResponseLabelIds, iter.Val.ResponseLabelIds...)
	}
	return resp, nil
}

func (s *ORGLabelSynchronizers) goAssemble(args ...interface{}) error {
	orgIDToResp := args[0].(cmap.ConcurrentMap[int, *trident.PrometheusLabelResponse])
	orgID := args[1].(int)
	reqLabels := args[2].([]*trident.MetricLabelRequest)
	c, err := cache.GetCache(orgID)
	if err != nil {
		return errors.Wrap(err, "GetCache")
	}
	synchronizer := newLabelSynchronizer(c)
	resp, err := synchronizer.assemble(&trident.PrometheusLabelRequest{RequestLabels: reqLabels})
	if err != nil {
		return errors.Wrap(err, "assemble")
	}
	orgIDToResp.Set(orgID, resp)
	s.appendStatsdCounter(synchronizer)
	return nil
}

func (s *ORGLabelSynchronizers) appendStatsdCounter(synchronizer *LabelSynchronizer) {
	atomic.AddUint64(&s.statsdCounter.ReceiveMetricCount, synchronizer.GetStatsdCounter().ReceiveMetricCount)
	atomic.AddUint64(&s.statsdCounter.ReceiveLabelCount, synchronizer.GetStatsdCounter().ReceiveLabelCount)
	atomic.AddUint64(&s.statsdCounter.SendMetricCount, synchronizer.GetStatsdCounter().SendMetricCount)
	atomic.AddUint64(&s.statsdCounter.SendLabelCount, synchronizer.GetStatsdCounter().SendLabelCount)
}

type LabelSynchronizer struct {
	Synchronizer
	grpcurl       *GRPCURL
	statsdCounter *statsd.PrometheusLabelIDsCounter
}

func newLabelSynchronizer(c *cache.Cache) *LabelSynchronizer {
	return &LabelSynchronizer{
		Synchronizer:  newSynchronizer(c),
		grpcurl:       new(GRPCURL),
		statsdCounter: statsd.NewPrometheusLabelIDsCounter(),
	}
}

func (s *LabelSynchronizer) GetStatsdCounter() *statsd.PrometheusLabelIDsCounter {
	return s.statsdCounter
}

func (s *LabelSynchronizer) assembleFully() (*trident.PrometheusLabelResponse, error) {
	resp := new(trident.PrometheusLabelResponse)
	mls, err := s.assembleMetricLabelFully()
	if err != nil {
		return nil, errors.Wrap(err, "assembleMetricLabelFully")
	}
	resp.ResponseLabelIds = mls

	ls, err := s.assembleLabelFully()
	if err != nil {
		return nil, errors.Wrap(err, "assembleLabelFully")
	}

	resp.OrgResponseLabels = []*trident.OrgLabelResponse{
		&trident.OrgLabelResponse{
			OrgId:          proto.Uint32(uint32(s.org.GetID())),
			ResponseLabels: ls,
		}}
	s.setStatsdCounter()
	return resp, err
}

func (s *LabelSynchronizer) assemble(req *trident.PrometheusLabelRequest) (*trident.PrometheusLabelResponse, error) {
	toEncode := s.splitData(req)

	err := s.prepare(toEncode)
	if err != nil {
		log.Error(s.org.Logf("prepare error: %+v", err))
		return nil, err
	}

	resp := new(trident.PrometheusLabelResponse)
	mls, err := s.assembleMetricLabel(req.GetRequestLabels())
	if err != nil {
		return nil, errors.Wrap(err, "assembleMetricLabel")
	}
	resp.ResponseLabelIds = mls
	return resp, nil
}

func (s *LabelSynchronizer) setStatsdCounter() {
	s.statsdCounter.SendMetricCount = s.counter.SendMetricCount
	s.statsdCounter.SendLabelCount = s.counter.SendLabelCount
}

func (s *LabelSynchronizer) prepare(toEncode *dataToEncode) error {
	if toEncode.cardinality() == 0 {
		return nil
	}

	syncResp, err := s.grpcurl.Sync(s.generateSyncRequest(toEncode))
	if err != nil {
		return errors.Wrap(err, "grpcurl.Sync")
	}
	eg := &errgroup.Group{}
	common.AppendErrGroup(eg, s.addMetricNameCache, syncResp.GetMetricNames())
	common.AppendErrGroup(eg, s.addLabelNameCache, syncResp.GetLabelNames())
	common.AppendErrGroup(eg, s.addLabelValueCache, syncResp.GetLabelValues())
	common.AppendErrGroup(eg, s.addMetricAPPLabelLayoutCache, syncResp.GetMetricAppLabelLayouts())
	common.AppendErrGroup(eg, s.addLabelCache, syncResp.GetLabels())
	return eg.Wait()
}

func (s *LabelSynchronizer) splitData(req *trident.PrometheusLabelRequest) *dataToEncode {
	toEncode := newDataToEncode(s.cache)
	for _, m := range req.GetRequestLabels() {
		mn := m.GetMetricName()
		toEncode.tryAppendMetricName(mn)
		for _, l := range m.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			toEncode.tryAppendLabelName(ln)
			toEncode.tryAppendLabelValue(lv)
			toEncode.tryAppendLabel(ln, lv)
			toEncode.tryAppendMetricAPPLabelLayout(mn, ln)
		}
	}

	return toEncode
}

func (s *LabelSynchronizer) generateSyncRequest(toEncode *dataToEncode) *controller.SyncPrometheusRequest {
	return &controller.SyncPrometheusRequest{
		OrgId:       proto.Uint32(uint32(s.org.GetID())),
		MetricNames: toEncode.metricNames.ToSlice(),
		LabelNames:  toEncode.labelNames.ToSlice(),
		LabelValues: toEncode.labelValues.ToSlice(),

		MetricAppLabelLayouts: func(ks []cache.LayoutKey) []*controller.PrometheusMetricAPPLabelLayoutRequest {
			res := make([]*controller.PrometheusMetricAPPLabelLayoutRequest, 0, len(ks))
			for i := range ks {
				res = append(res, &controller.PrometheusMetricAPPLabelLayoutRequest{
					MetricName:   &ks[i].MetricName,
					AppLabelName: &ks[i].LabelName,
				})
			}
			return res
		}(toEncode.metricAPPLabelLayouts.ToSlice()),

		Labels: func(ks []cache.LabelKey) []*controller.PrometheusLabelRequest {
			res := make([]*controller.PrometheusLabelRequest, 0, len(ks))
			for i := range ks {
				res = append(res, &controller.PrometheusLabelRequest{
					Name:  &ks[i].Name,
					Value: &ks[i].Value,
				})
			}
			return res
		}(toEncode.labels.ToSlice()),
	}
}

func (s *LabelSynchronizer) assembleMetricLabel(mls []*trident.MetricLabelRequest) ([]*trident.MetricLabelResponse, error) {
	respMLs := make([]*trident.MetricLabelResponse, 0)

	nonMetricNameToCount := make(map[string]int, 0) // used to count how many times a nonexistent metric name appears, avoid swiping log
	nonLabelNames := mapset.NewSet[string]()
	nonLabelValues := mapset.NewSet[string]()
	for _, ml := range mls {
		s.statsdCounter.ReceiveMetricCount++
		s.statsdCounter.ReceiveLabelCount += uint64(len(ml.GetLabels()))

		var rls []*trident.LabelResponse
		mn := ml.GetMetricName()
		mni, ok := s.cache.MetricName.GetIDByName(mn)
		if !ok {
			nonMetricNameToCount[mn]++
			continue
		}

		for _, l := range ml.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			ni, ok := s.cache.LabelName.GetIDByName(ln)
			if !ok {
				nonLabelNames.Add(ln)
				continue
			}
			vi, ok := s.cache.LabelValue.GetIDByValue(lv)
			if !ok {
				nonLabelValues.Add(lv)
				continue
			}
			id, _ := s.cache.MetricAndAPPLabelLayout.GetIndexByKey(cache.NewLayoutKey(mn, ln))
			rls = append(rls, &trident.LabelResponse{
				Name:                &ln,
				NameId:              proto.Uint32(uint32(ni)),
				Value:               &lv,
				ValueId:             proto.Uint32(uint32(vi)),
				AppLabelColumnIndex: proto.Uint32(uint32(id)),
			})
			s.statsdCounter.SendLabelCount++
		}
		respMLs = append(respMLs, &trident.MetricLabelResponse{
			OrgId:        proto.Uint32(uint32(s.org.GetID())),
			MetricName:   &mn,
			MetricId:     proto.Uint32(uint32(mni)),
			LabelIds:     rls,
			PodClusterId: proto.Uint32(uint32(ml.GetPodClusterId())),
			EpcId:        proto.Uint32(uint32(ml.GetEpcId())),
		})
		s.statsdCounter.SendMetricCount++
		// }
	}
	if len(nonMetricNameToCount) != 0 {
		log.Error(s.org.Logf("metric name id not found, name to request count: %+v", nonMetricNameToCount))
	}
	if nonLabelNames.Cardinality() > 0 {
		log.Error(s.org.Logf("label name id not found, names: %v", nonLabelNames.ToSlice()))
	}
	if nonLabelValues.Cardinality() > 0 {
		log.Error(s.org.Logf("label value id not found, values: %v", nonLabelValues.ToSlice()))
	}
	return respMLs, nil
}

func (s *LabelSynchronizer) addMetricNameCache(arg ...interface{}) error {
	mns := arg[0].([]*controller.PrometheusMetricName)
	s.cache.MetricName.Add(mns)
	return nil
}

func (s *LabelSynchronizer) addLabelNameCache(arg ...interface{}) error {
	lns := arg[0].([]*controller.PrometheusLabelName)
	s.cache.LabelName.Add(lns)
	return nil
}

func (s *LabelSynchronizer) addLabelValueCache(arg ...interface{}) error {
	lvs := arg[0].([]*controller.PrometheusLabelValue)
	s.cache.LabelValue.Add(lvs)
	return nil
}

func (s *LabelSynchronizer) addMetricAPPLabelLayoutCache(arg ...interface{}) error {
	ls := arg[0].([]*controller.PrometheusMetricAPPLabelLayout)
	s.cache.MetricAndAPPLabelLayout.Add(ls)
	return nil
}

func (s *LabelSynchronizer) addLabelCache(arg ...interface{}) error {
	ls := arg[0].([]*controller.PrometheusLabel)
	s.cache.Label.Add(ls)
	return nil
}

type dataToEncode struct {
	cache *cache.Cache

	metricNames            mapset.Set[string]
	labelNames             mapset.Set[string]
	labelValues            mapset.Set[string]
	metricAPPLabelLayouts  mapset.Set[cache.LayoutKey]
	labels                 mapset.Set[cache.LabelKey]
	metricNameToLabelNames map[string]mapset.Set[string]
}

func newDataToEncode(c *cache.Cache) *dataToEncode {
	return &dataToEncode{
		cache: c,

		metricNames:            mapset.NewSet[string](),
		labelNames:             mapset.NewSet[string](),
		labelValues:            mapset.NewSet[string](),
		metricAPPLabelLayouts:  mapset.NewSet[cache.LayoutKey](),
		labels:                 mapset.NewSet[cache.LabelKey](),
		metricNameToLabelNames: make(map[string]mapset.Set[string], 0),
	}
}

func (d *dataToEncode) cardinality() int {
	return d.metricNames.Cardinality() + d.labelNames.Cardinality() + d.labelValues.Cardinality() +
		d.metricAPPLabelLayouts.Cardinality() + d.labels.Cardinality() + len(d.metricNameToLabelNames)
}

func (d *dataToEncode) tryAppendMetricName(name string) {
	if _, ok := d.cache.MetricName.GetIDByName(name); !ok {
		d.metricNames.Add(name)
	}
}

func (d *dataToEncode) tryAppendLabelName(name string) {
	if _, ok := d.cache.LabelName.GetIDByName(name); !ok {
		d.labelNames.Add(name)
	}
}

func (d *dataToEncode) tryAppendLabelValue(value string) {
	if _, ok := d.cache.LabelValue.GetIDByValue(value); !ok {
		d.labelValues.Add(value)
	}
}

func (d *dataToEncode) tryAppendMetricAPPLabelLayout(metricName, labelName string) {
	k := cache.NewLayoutKey(metricName, labelName)
	if _, ok := d.cache.MetricAndAPPLabelLayout.GetIndexByKey(k); !ok {
		d.metricAPPLabelLayouts.Add(k)
	}
}

func (d *dataToEncode) appendMetricAPPLabelLayout(metricName, labelName string) {
	d.metricAPPLabelLayouts.Add(cache.NewLayoutKey(metricName, labelName))
}

func (d *dataToEncode) tryAppendLabel(name, value string) {
	if _, ok := d.cache.Label.GetIDByKey(cache.NewLabelKey(name, value)); !ok {
		d.labels.Add(cache.NewLabelKey(name, value))
	}
}
