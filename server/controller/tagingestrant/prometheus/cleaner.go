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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/bitly/go-simplejson"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/tagingestrant/prometheus/cache"
	prometheuscommon "github.com/deepflowio/deepflow/server/controller/tagingestrant/prometheus/common"
	prometheuscfg "github.com/deepflowio/deepflow/server/controller/tagingestrant/prometheus/config"
	"github.com/deepflowio/deepflow/server/controller/tagingestrant/prometheus/encoder"
	queriercfg "github.com/deepflowio/deepflow/server/querier/config"
)

var (
	cleanerOnce sync.Once
	cleaner     *Cleaner
)

type Cleaner struct {
	ctx    context.Context
	cancel context.CancelFunc

	canClean chan struct{}
	cfg      prometheuscfg.Config
}

func GetCleaner() *Cleaner {
	cleanerOnce.Do(func() {
		cleaner = &Cleaner{
			canClean: make(chan struct{}, 1),
		}
	})
	return cleaner
}

func (c *Cleaner) Init(ctx context.Context, cfg prometheuscfg.Config) {
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.cfg = cfg
	c.canClean <- struct{}{}
}

func (c *Cleaner) Start(sCtx context.Context) error {
	log.Info("prometheus data cleaner started")
	go func() {
		ticker := time.NewTicker(time.Duration(c.cfg.DataCleanInterval) * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-sCtx.Done():
				return
			case <-ticker.C:
				c.clear()
			}
		}
	}()
	return nil
}

func (c *Cleaner) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	log.Info("prometheus data cleaner stopped")
}

func (c *Cleaner) clear() error {
	select {
	case <-c.canClean:
		c.deleteAndRefresh()
		c.canClean <- struct{}{}
		return nil
	default:
		log.Info("prometheus data cleaner clear skipped")
		return errors.New("cleaner is busy, try again later")
	}
}

func (c *Cleaner) deleteAndRefresh() error {
	log.Info("prometheus data cleaner clear started")
	defer log.Info("prometheus data cleaner clear completed")

	if orgIDs, err := mysql.GetORGIDs(); err != nil {
		log.Errorf("failed to get org ids: %v", err)
		return err
	} else {
		for _, orgID := range orgIDs {
			org, err := prometheuscommon.NewORG(orgID)
			if err != nil {
				log.Errorf("failed to new org: %v", err)
				return err
			}
			if err := newDeleter(org, c.cfg).tryDelete(); err != nil {
				log.Errorf("failed to delete: %v", err)
				return err
			}
		}
	}
	return nil
}

type deleter struct {
	cfg prometheuscfg.Config
	org *prometheuscommon.ORG

	activeData  *activeData
	dataToCheck *dataToCheck

	deleted bool // check if any data is deleted, refresh related data if necessary
}

func newDeleter(org *prometheuscommon.ORG, cfg prometheuscfg.Config) *deleter {
	return &deleter{
		org: org,
		cfg: cfg,
	}
}

func (d *deleter) tryDelete() error {
	if err := d.prepareData(); err != nil {
		return err
	}
	d.delete()
	if !d.deleted {
		return nil
	}
	return d.refreshRelatedData()
}

func (d *deleter) refreshRelatedData() error {
	en, err := encoder.GetEncoder(d.org.GetID())
	if err != nil {
		log.Error(d.org.Logf("failed to get encoder: %v", err))
	} else {
		en.Refresh()
	}
	return d.org.GetDB().Model(&mysql.ResourceVersion{}).Where("name = ?", versionName).Update("version", uint32(time.Now().Unix())).Error
}

func (d *deleter) prepareData() error {
	querier, err := newQuerier(d.org, d.cfg.QuerierQueryLimit)
	if err != nil {
		log.Error(d.org.Logf("failed to new querier: %v", err))
		return err
	}
	if d.activeData, err = querier.query(); err != nil {
		log.Error(d.org.Logf("failed to get active data: %v", err))
		return err
	}

	d.dataToCheck = newDataToCheck()
	if err := d.dataToCheck.load(d.org.DB); err != nil {
		log.Error(d.org.Logf("failed to load data to check: %v", err))
		return err
	}
	return nil
}

func (c *deleter) delete() error {
	var e error
	if err := c.deleteExpiredMetricAPPLabelLayout(); err != nil {
		log.Error(c.org.Logf("mysql delete failed: %v", err))
		e = err
	}
	if err := c.deleteExpiredMetricName(); err != nil {
		log.Error(c.org.Logf("mysql delete failed: %v", err))
		e = err
	}
	if err := c.deleteExpiredLabel(); err != nil {
		log.Error(c.org.Logf("mysql delete failed: %v", err))
		e = err
	}
	if err := c.deleteExpiredLabelName(); err != nil {
		log.Error(c.org.Logf("mysql delete failed: %v", err))
		e = err
	}
	if err := c.deleteExpiredLabelValue(); err != nil {
		log.Error(c.org.Logf("mysql delete failed: %v", err))
		e = err
	}
	return e
}

func (d *deleter) whetherDeleted(resourceCountToDelete int) bool {
	if resourceCountToDelete > 0 {
		d.deleted = true
	}
	return d.deleted
}

func (d *deleter) deleteExpiredMetricName() error {
	toDelete := make([]mysql.PrometheusMetricName, 0)
	for _, item := range d.dataToCheck.metricNames {
		if !d.activeData.getMetricName(item.Name) {
			toDelete = append(toDelete, item)
		}
	}
	if !d.whetherDeleted(len(toDelete)) {
		return nil
	}
	return DeleteBatch(prometheuscommon.ResourcePrometheusMetricName, d.org.DB, toDelete)
}

func (d *deleter) deleteExpiredLabel() error {
	toDelete := make([]mysql.PrometheusLabel, 0)
	for _, item := range d.dataToCheck.labels {
		if !d.activeData.getLabel(item.Name, item.Value) {
			toDelete = append(toDelete, item)
		}
	}
	if !d.whetherDeleted(len(toDelete)) {
		return nil
	}
	return DeleteBatch(prometheuscommon.ResourcePrometheusLabel, d.org.DB, toDelete)
}

func (d *deleter) deleteExpiredLabelName() error {
	toDelete := make([]mysql.PrometheusLabelName, 0)
	for _, item := range d.dataToCheck.labelNames {
		if !d.activeData.getLabelName(item.Name) {
			toDelete = append(toDelete, item)
		}
	}
	if !d.whetherDeleted(len(toDelete)) {
		return nil
	}
	return DeleteBatch(prometheuscommon.ResourcePrometheusLabelName, d.org.DB, toDelete)
}

func (d *deleter) deleteExpiredLabelValue() error {
	toDelete := make([]mysql.PrometheusLabelValue, 0)
	for _, item := range d.dataToCheck.labelValues {
		if !d.activeData.getLabelValue(item.Value) {
			toDelete = append(toDelete, item)
		}
	}
	if !d.whetherDeleted(len(toDelete)) {
		return nil
	}
	return DeleteBatch(prometheuscommon.ResourcePrometheusLabelValue, d.org.DB, toDelete)
}

func (d *deleter) deleteExpiredMetricAPPLabelLayout() error {
	toDelete := make([]mysql.PrometheusMetricAPPLabelLayout, 0)
	for _, item := range d.dataToCheck.metricAPPLabelLayouts {
		if !d.activeData.getMetricLabelName(item.MetricName, item.APPLabelName) {
			toDelete = append(toDelete, item)
		}
	}
	if !d.whetherDeleted(len(toDelete)) {
		return nil
	}
	return DeleteBatch(prometheuscommon.ResourcePrometheusMetricAPPLabelLayout, d.org.DB, toDelete)
}

func DeleteBatch[MT any](resourceType string, db *mysql.DB, items []MT) error {
	count := len(items)
	offset := 5000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		toDel := items[start:end]
		if err := db.Delete(&toDel).Error; err != nil {
			log.Error(db.Logf("mysql delete %s failed: %v", resourceType, err))
			return err
		}
		log.Info(db.Logf("clear %s data count: %d", resourceType, len(toDel)))
		log.Debugf(db.Logf("clear %s data: %#v", resourceType, toDel))
	}

	return nil
}

var (
	queryLabel       = "label"
	queryMetricLabel = "metric_label"
)

type querier struct {
	org        *prometheuscommon.ORG
	reqBody    map[string]url.Values
	activeData *activeData
	queryLimit int
}

func newQuerier(org *prometheuscommon.ORG, queryLimit int) (*querier, error) {
	c, err := cache.GetCache(org.GetID())
	if err != nil {
		log.Error(org.Logf("failed to get cache: %v", err))
		return nil, err
	}
	queryBody := map[string]url.Values{
		queryMetricLabel: url.Values{
			"db":  {"_prometheus"},
			"sql": {"show tags"},
		},
		queryLabel: url.Values{
			"db":  {"_prometheus"},
			"sql": {"show tag-values"},
		},
	}
	for _, body := range queryBody {
		body.Set("sql", fmt.Sprintf("%s limit %d", body.Get("sql"), queryLimit))
	}
	return &querier{
		org:        org,
		reqBody:    queryBody,
		activeData: newActiveData(c),
		queryLimit: queryLimit,
	}, nil
}

func (q *querier) query() (*activeData, error) {
	regionToDomainNamePrefix, err := q.getRegionToDomainNamePrefix()
	if err != nil {
		return nil, err
	}
	for region, domainNamePrefix := range regionToDomainNamePrefix {
		log.Info(q.org.Logf("get active data by region: %s", region))
		if err := q.getMetricLabelAndFillActiveData(domainNamePrefix); err != nil {
			return nil, err
		}
		if err := q.getLabelAndFillActiveData(domainNamePrefix); err != nil {
			return nil, err
		}
	}
	log.Infof(q.org.Logf("active data cardinality: %s", q.activeData.getCardinalityInfo()))
	return q.activeData, nil
}

func (q *querier) getMetricLabelAndFillActiveData(domainNamePrefix string) error {
	resp, err := q.getByRegion(domainNamePrefix, queryMetricLabel)
	if err != nil {
		return err
	}
	result := resp.Get("result")
	var labelNameIdx, metricNameIdx int
	cols := result.Get("columns").MustArray()
	for i, col := range cols {
		if col == "name" {
			labelNameIdx = i
		} else if col == "table" {
			metricNameIdx = i
		}
	}

	log.Infof(q.org.Logf("active metric label count: %d", len(result.Get("values").MustArray())))
	for i := range result.Get("values").MustArray() {
		value := result.Get("values").GetIndex(i)
		metricName := value.GetIndex(metricNameIdx).MustString()
		if metricName == "" {
			continue
		}
		labelName := value.GetIndex(labelNameIdx).MustString()

		q.activeData.appendMetricName(metricName)
		q.activeData.appendLabelName(labelName)
		q.activeData.appendMetricLabelName(metricName, labelName)
	}
	return nil
}

func (q *querier) getLabelAndFillActiveData(domainNamePrefix string) error {
	resp, err := q.getByRegion(domainNamePrefix, queryLabel)
	if err != nil {
		return err
	}
	result := resp.Get("result")
	var labelNameIdx, labelValueIdx int
	cols := result.Get("columns").MustArray()
	for i, col := range cols {
		if col == "label_name" {
			labelNameIdx = i
		} else if col == "label_value" {
			labelValueIdx = i
		}
	}

	log.Infof(q.org.Logf("active label count: %d", len(result.Get("values").MustArray())))
	for i := range result.Get("values").MustArray() {
		value := result.Get("values").GetIndex(i)
		labelName := value.GetIndex(labelNameIdx).MustString()
		labelValue := value.GetIndex(labelValueIdx).MustString()
		q.activeData.appendLabelName(labelName)
		q.activeData.appendLabelValue(labelValue)
		q.activeData.appendLabel(labelName, labelValue)
	}
	return nil
}

func (q *querier) getByRegion(domainNamePrefix string, resourceType string) (*simplejson.Json, error) {
	url := fmt.Sprintf("http://%sdeepflow-server:%d/v1/query", domainNamePrefix, queriercfg.Cfg.ListenPort)
	log.Infof(q.org.Logf("get active data: %s, body: %v", url, q.reqBody[resourceType]))
	resp, err := common.CURLForm(
		http.MethodPost,
		url,
		q.reqBody[resourceType],
		common.WithORGHeader(strconv.Itoa(q.org.GetID())),
	)
	if err != nil {
		log.Error(q.org.Logf("failed to get raw data: %s, %s", err.Error(), url))
		return nil, err
	}
	// FIXME better exceed handling
	if len(resp.Get("result").Get("values").MustArray()) >= q.queryLimit {
		return nil, fmt.Errorf("the count of %s exceeded the query limit: %d", resourceType, q.queryLimit)
	}
	return resp, nil
}

func (q *querier) getRegionToDomainNamePrefix() (map[string]string, error) {
	var controllers []*mysql.Controller
	if err := q.org.DB.Find(&controllers).Error; err != nil {
		log.Error(q.org.Logf("failed to query %s: %v", "controller", err))
		return nil, err
	}
	ipToControllerDomainPrefix := make(map[string]string)
	for _, controller := range controllers {
		if controller.NodeType == common.CONTROLLER_NODE_TYPE_MASTER {
			ipToControllerDomainPrefix[controller.IP] = ""
			continue
		}
		ipToControllerDomainPrefix[controller.IP] = controller.RegionDomainPrefix
	}

	var azControllerConns []*mysql.AZControllerConnection
	if err := q.org.DB.Find(&azControllerConns).Error; err != nil {
		log.Error(q.org.Logf("failed to query %s: %v", "az_controller_connection", err))
		return nil, err
	}

	regionToDomainNamePrefix := make(map[string]string)
	for _, conn := range azControllerConns {
		if _, ok := regionToDomainNamePrefix[conn.Region]; ok {
			continue
		}
		if domainNamePrefix, ok := ipToControllerDomainPrefix[conn.ControllerIP]; ok {
			regionToDomainNamePrefix[conn.Region] = domainNamePrefix
		}
	}
	return regionToDomainNamePrefix, nil
}

type activeData struct {
	metricNames      map[string]struct{}             // for prometheus_metric_name
	labelNames       map[string]struct{}             // for prometheus_label_name
	labelValues      map[string]struct{}             // for prometheus_label_value
	labels           map[labelKey]struct{}           // for prometheus_label
	metricLabelNames map[metricLabelNameKey]struct{} // for prometheus_metric_label_name, prometheus_metric_app_label_layout
}

func newActiveData(c *cache.Cache) *activeData {
	return &activeData{
		metricNames:      make(map[string]struct{}),
		labelNames:       make(map[string]struct{}),
		labelValues:      make(map[string]struct{}),
		labels:           make(map[labelKey]struct{}),
		metricLabelNames: make(map[metricLabelNameKey]struct{}),
	}
}

func (d *activeData) getCardinalityInfo() string {
	return fmt.Sprintf(
		"metricNames: %d, labelNames: %d, labelValues: %d, labelNameToValue: %d, metricNameToLabelName: %d",
		len(d.metricNames), len(d.labelNames), len(d.labelValues), len(d.labels), len(d.metricLabelNames),
	)
}

func (d *activeData) getMetricName(name string) bool {
	_, ok := d.metricNames[name]
	return ok
}

func (d *activeData) getLabelName(name string) bool {
	_, ok := d.labelNames[name]
	return ok
}

func (d *activeData) getLabelValue(value string) bool {
	_, ok := d.labelValues[value]
	return ok
}

func (d *activeData) getLabel(name, value string) bool {
	_, ok := d.labels[newLabelKey(name, value)]
	return ok
}

func (d *activeData) getMetricLabelName(metricName, labelName string) bool {
	_, ok := d.metricLabelNames[newMetricLabelNameKey(metricName, labelName)]
	return ok
}

func (d *activeData) appendMetricName(name string) {
	d.metricNames[name] = struct{}{}
}

func (d *activeData) appendLabelName(name string) {
	d.labelNames[name] = struct{}{}
}

func (d *activeData) appendLabelValue(value string) {
	d.labelValues[value] = struct{}{}
}

func (d *activeData) appendLabel(name, value string) {
	d.labels[newLabelKey(name, value)] = struct{}{}
}

func (d *activeData) appendMetricLabelName(metricName, labelName string) {
	d.metricLabelNames[newMetricLabelNameKey(metricName, labelName)] = struct{}{}
}

type metricLabelNameKey struct {
	metricName string
	labelName  string
}

func newMetricLabelNameKey(metricName, labelName string) metricLabelNameKey {
	return metricLabelNameKey{
		metricName: metricName,
		labelName:  labelName,
	}
}

type labelKey struct {
	name  string
	value string
}

func newLabelKey(name, value string) labelKey {
	return labelKey{
		name:  name,
		value: value,
	}
}

type dataToCheck struct {
	metricNames           []mysql.PrometheusMetricName
	labelNames            []mysql.PrometheusLabelName
	labelValues           []mysql.PrometheusLabelValue
	labels                []mysql.PrometheusLabel
	metricAPPLabelLayouts []mysql.PrometheusMetricAPPLabelLayout
}

func newDataToCheck() *dataToCheck {
	return &dataToCheck{
		metricNames:           make([]mysql.PrometheusMetricName, 0),
		labelNames:            make([]mysql.PrometheusLabelName, 0),
		labelValues:           make([]mysql.PrometheusLabelValue, 0),
		labels:                make([]mysql.PrometheusLabel, 0),
		metricAPPLabelLayouts: make([]mysql.PrometheusMetricAPPLabelLayout, 0),
	}
}

func (c *dataToCheck) getRetentionTime(db *mysql.DB) time.Time {
	var dataSource *mysql.DataSource
	db.Where("display_name = ?", "Prometheus 数据").Find(&dataSource)
	dataSourceRetentionHours := 7 * 24
	if dataSource != nil {
		dataSourceRetentionHours = dataSource.RetentionTime
	}
	return time.Now().Add(time.Duration(-dataSourceRetentionHours) * time.Hour)
}

// load loads data created before retention time
func (d *dataToCheck) load(db *mysql.DB) error {
	var err error
	retentionTime := d.getRetentionTime(db)
	if d.metricNames, err = prometheuscommon.WhereFind[mysql.PrometheusMetricName](db, "created_at < ?", retentionTime); err != nil {
		return err
	}
	if d.labelNames, err = prometheuscommon.WhereFind[mysql.PrometheusLabelName](db, "created_at < ?", retentionTime); err != nil {
		return err
	}
	if d.labelValues, err = prometheuscommon.WhereFind[mysql.PrometheusLabelValue](db, "created_at < ?", retentionTime); err != nil {
		return err
	}
	if d.labels, err = prometheuscommon.WhereFind[mysql.PrometheusLabel](db, "created_at < ?", retentionTime); err != nil {
		return err
	}
	if d.metricAPPLabelLayouts, err = prometheuscommon.WhereFind[mysql.PrometheusMetricAPPLabelLayout](db, "created_at < ?", retentionTime); err != nil {
		return err
	}
	return nil
}
