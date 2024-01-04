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

package store

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/influxdata/influxdb/client/v2"

	"github.com/deepflowio/deepflow/server/libs/zerodoc"
)

const (
	SUCCESS = "success"
	FAILED  = "failed"
)

var dbGroupsMap = map[string][]string{
	"vtap_flow":   []string{"vtap_flow", "vtap_flow_edge", "vtap_flow_edge_port", "vtap_flow_port"},
	"vtap_packet": []string{"vtap_packet", "vtap_packet_edge"},
	"vtap_wan":    []string{"vtap_wan", "vtap_wan_port"},
}

// zerodoc 的 Latency 结构中的字段都是 非累加聚合
var unsumableFieldsMap = map[string]bool{
	"rtt":            true,
	"rtt_client":     true,
	"rtt_server":     true,
	"srt":            true,
	"art":            true,
	"http_rrt":       true,
	"dns_rrt":        true,
	"rtt_max":        true,
	"rtt_client_max": true,
	"rtt_server_max": true,
	"srt_max":        true,
	"art_max":        true,
	"http_rrt_max":   true,
	"dns_rrt_max":    true,
}

type ActionEnum uint8

const (
	ADD ActionEnum = iota
	DEL
	MOD
	SHOW
	UPDATE // 若版本升级，新增field，支持更新CQ
)

var actionsMap = map[string]ActionEnum{
	"add":    ADD,
	"del":    DEL,
	"mod":    MOD,
	"show":   SHOW,
	"update": UPDATE,
}

type AggrEnum uint8

const (
	SUM AggrEnum = iota
	MAX
	MIN
	AVG
)

func (a AggrEnum) String() string {
	switch a {
	case SUM:
		return "sum"
	case MAX:
		return "max"
	case MIN:
		return "min"
	case AVG:
		return "mean"
	}
	return ""
}

var aggrsMap = map[string]AggrEnum{
	"sum": SUM,
	"max": MAX,
	"min": MIN,
	"avg": AVG,
}

type CLIHandler struct {
	action     ActionEnum
	rpHandlers []*RPHandler
	cqHandlers []*CQHandler
}

type RPHandler struct {
	client        client.Client
	action        ActionEnum
	db            string
	rp            string
	duration      int // 小时
	shardDuration int // 小时
}

type CQHandler struct {
	client         client.Client
	db             string
	srcRP          string
	dstRP          string
	interval       string // 分钟 <xx>m
	aggrSummable   AggrEnum
	aggrUnsummable AggrEnum
}

func initHttpClient(httpAddr, user, password string) (client.Client, error) {
	HTTPConfig := client.HTTPConfig{Addr: httpAddr, Username: user, Password: password}
	httpClient, err := client.NewHTTPClient(HTTPConfig)
	if err != nil {
		log.Error("create influxdb http client failed:", err)
		return nil, err
	}

	if _, _, err = httpClient.Ping(0); err != nil {
		log.Errorf("http connect to influxdb(%s) failed: %s", httpAddr, err)
		return nil, err
	}
	return httpClient, nil
}

type CQInfo struct {
	db      string
	name    string
	content string
}

func GetCQInfos(httpClient client.Client) ([]CQInfo, error) {
	rows, err := queryRows(httpClient, "", "", "show continuous queries")
	if err != nil {
		return nil, err
	}

	cqInfos := make([]CQInfo, 0)
	for _, row := range rows {
		for _, values := range row.Values {
			if len(values) < 2 {
				continue
			}
			cqInfos = append(cqInfos, CQInfo{
				db:      row.Name,
				name:    values[0].(string),
				content: values[1].(string),
			})
		}
	}
	return cqInfos, nil
}

func GetRetentionPolicies(httpClient client.Client, db string) ([]string, error) {
	response, err := httpClient.Query(client.Query{Command: fmt.Sprintf("SHOW RETENTION POLICIES ON %q", db)})
	if err := checkResponse(response, err); err != nil {
		log.Warningf("DB(%s) get retention policies failed: %s", db, err)
		return nil, err
	}

	rps := make([]string, 0, 4)
	for _, result := range response.Results {
		for _, row := range result.Series {
			for _, values := range row.Values {
				if len(values) > 0 {
					rps = append(rps, values[0].(string))
				}
			}
		}
	}
	return rps, nil
}

// CREATE CONTINUOUS QUERY cq_rp_1h__packet_rx ON vtap_flow_port BEGIN SELECT sum(packet_rx) AS packet_rx INTO vtap_flow_port.rp_1h.main FROM vtap_flow_port.rp_1m.main GROUP BY time(1h), * TZ('Asia/Shanghai') END
func parseCqContent(cq string) (aggr string, srcRP string, interval string, err error) {
	sections := strings.Split(cq, " ")
	sections = append(sections, "") //增加一个空段，不用匹配

	for i, key := range sections {
		// 最后一个不匹配
		if i+1 == len(sections) {
			break
		}
		value := sections[i+1]
		switch key {
		case "SELECT":
			for k, v := range aggrsMap {
				if strings.Index(value, v.String()+"(") > -1 {
					aggr = k
					break
				}
			}
		case "FROM":
			srcRP = strings.Split(value, ".")[1]
		case "BY":
			begin := strings.Index(value, "(")
			end := strings.Index(value, ")")
			intervalDuration, e := time.ParseDuration(value[begin+1 : end])
			if e != nil {
				err = fmt.Errorf("parse interval(%s) failed(%s)", value, e)
				return
			}
			// 转化为分钟
			interval = strconv.Itoa(int(intervalDuration / time.Minute))
		}
	}
	return
}

func GetCQParams(cqInfos []CQInfo, db, rp string) *CQHandler {
	summableCqName := "cq_" + rp + "__packet_rx"
	unsummableCqName := "cq_" + rp + "__rtt"
	var srcRP, interval, aggrSummable, aggrUnsummable string
	var err error
	for _, cqInfo := range cqInfos {
		if cqInfo.db == db && cqInfo.name == summableCqName {
			aggrSummable, srcRP, interval, err = parseCqContent(cqInfo.content)
			if err != nil {
				return nil
			}
			if aggrUnsummable != "" {
				break
			}
		}
		if cqInfo.db == db && cqInfo.name == unsummableCqName {
			aggrUnsummable, _, _, err = parseCqContent(cqInfo.content)
			if err != nil {
				return nil
			}
			if aggrSummable != "" {
				break
			}
		}
	}
	if aggrSummable == "" {
		return nil
	}
	return &CQHandler{
		db:             db,
		srcRP:          srcRP,
		dstRP:          rp,
		interval:       interval,
		aggrSummable:   aggrsMap[aggrSummable],
		aggrUnsummable: aggrsMap[aggrUnsummable],
	}
}

/*
提供给droplet-ctl调用, 实现更新CQ:

	1, 查询vtap_flow, vtap_packet, vtap_wan数据库的RP和CQ信息，提取CQ的参数
	  - 包括原RP，目的RP，聚合时长，可累加聚合信息（以packet_rx为准），不可累加聚合(以rtt的处理为准)
	2，对所有的数据库根据获取的CQ参数和当前的field信息再次下发CQ，
	  - 若有新增field，则会对新增的field增加CQ命令
	  - 若无新增field，则对已有的CQ重复下发，若和原来的CQ参数不一致，则报错。
*/
func UpdateCQs(httpAddr, user, password string) error {
	httpClient, err := initHttpClient(httpAddr, user, password)
	if err != nil {
		return err
	}

	cqInfos, err := GetCQInfos(httpClient)
	if err != nil {
		return err
	}

	for db, _ := range dbGroupsMap {
		rps, err := GetRetentionPolicies(httpClient, db)
		if err != nil {
			return err
		}

		for _, rp := range rps {
			if rp == "rp_1s" || rp == "rp_1m" || rp == "autogen" {
				continue
			}
			if !strings.HasPrefix(rp, "rp_") {
				continue
			}

			cqHandler := GetCQParams(cqInfos, db, rp)
			if cqHandler == nil {
				continue
			}
			interval, _ := strconv.Atoi(cqHandler.interval)
			aggrSummable := cqHandler.aggrSummable.String()
			if aggrSummable == "mean" {
				aggrSummable = "avg"
			}
			aggrUnsummable := cqHandler.aggrUnsummable.String()
			if aggrUnsummable == "mean" {
				aggrUnsummable = "avg"
			}
			cli, err := NewCLIHandler(httpAddr, user, password, db, "update",
				cqHandler.srcRP, cqHandler.dstRP, aggrSummable, aggrUnsummable, "", interval, 168)
			log.Info("CQ update:", db, cqHandler.srcRP, cqHandler.dstRP, aggrSummable, aggrUnsummable, interval)
			fmt.Printf("CQ update: dbGroup:%s srcRP:%s dstRP:%s aggrSummable:%s aggrUnsummable:%s interval:%dm\n", db, cqHandler.srcRP, cqHandler.dstRP, aggrSummable, aggrUnsummable, interval)
			if err != nil {
				return err
			}
			_, err = cli.Run()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func NewCLIHandler(httpAddr, user, password, dbGroup, action, baseRP, newRP, aggrSummable, aggrUnsummable, RPPrefix string, CQInterval, RPDuration int) (*CLIHandler, error) {
	HTTPConfig := client.HTTPConfig{Addr: httpAddr, Username: user, Password: password}
	httpClient, err := client.NewHTTPClient(HTTPConfig)
	if err != nil {
		log.Error("create influxdb http client failed:", err)
		return nil, err
	}

	if _, _, err = httpClient.Ping(0); err != nil {
		log.Errorf("http connect to influxdb(%s) failed: %s", httpAddr, err)
		return nil, err
	}
	dbs, ok := dbGroupsMap[dbGroup]
	if !ok {
		return nil, fmt.Errorf("unsupport dbGroup: %s", dbGroup)
	}
	if _, ok := actionsMap[action]; !ok {
		return nil, fmt.Errorf("unsupport action: %s", action)
	}
	actionEnum := actionsMap[action]
	RPDuration += 2 // 默认多加2小时，防止CQ时数据未写入

	shardDuration := 24
	if actionEnum == ADD || actionEnum == UPDATE {
		if baseRP == "" {
			return nil, fmt.Errorf("src rp name is empty")
		}
		if _, ok := aggrsMap[aggrSummable]; !ok {
			return nil, fmt.Errorf("unsupport aggr summable: %s", aggrSummable)
		}
		if _, ok := aggrsMap[aggrUnsummable]; !ok {
			return nil, fmt.Errorf("unsupport aggr unsummable: %s", aggrUnsummable)
		}
		if CQInterval < 1 {
			return nil, fmt.Errorf("CQ interval(%d) must bigger than 0. ", CQInterval)
		}
		if RPDuration < 0 {
			return nil, fmt.Errorf("RPDuration(%d) must not smaller than 0. ", RPDuration)
		}
		// 1小时内的聚合
		if CQInterval < 60 {
			shardDuration = 2 * 24
		}
		// 1小时 到 1天内的聚合
		if CQInterval >= 60 && CQInterval < 60*24 {
			shardDuration = 7 * 24
		}
		// 大于1天
		if CQInterval >= 60*24 {
			shardDuration = 15 * 24
		}
		if shardDuration > RPDuration {
			shardDuration = RPDuration
		}
		if baseRP == newRP {
			return nil, fmt.Errorf("base-rp(%s) should not the same as the rpname(%s)", baseRP, newRP)
		}
	}

	if actionEnum != SHOW && newRP == "" {
		return nil, fmt.Errorf("rp name is empty")
	}

	baseRP = RPPrefix + baseRP
	newRP = RPPrefix + newRP
	rpHandlers := make([]*RPHandler, len(dbs))
	cqHandlers := make([]*CQHandler, len(dbs))
	for i, db := range dbs {
		rpHandlers[i] = &RPHandler{
			client:        httpClient,
			action:        actionsMap[action],
			db:            db,
			rp:            newRP,
			duration:      RPDuration,
			shardDuration: shardDuration,
		}
		cqHandlers[i] = &CQHandler{
			client:         httpClient,
			db:             db,
			srcRP:          baseRP,
			dstRP:          newRP,
			interval:       fmt.Sprintf("%dm", CQInterval),
			aggrSummable:   aggrsMap[aggrSummable],
			aggrUnsummable: aggrsMap[aggrUnsummable],
		}
	}

	return &CLIHandler{
		action:     actionEnum,
		rpHandlers: rpHandlers,
		cqHandlers: cqHandlers,
	}, nil
}

func (c *CLIHandler) Run() (string, error) {
	ret := SUCCESS
	for i, rpHandler := range c.rpHandlers {
		cqHandlers := c.cqHandlers[i]
		switch c.action {
		case ADD:
			if err := createDefaultRPIfNotExist(cqHandlers.client, cqHandlers.db, cqHandlers.srcRP); err != nil {
				return FAILED, err
			}
			if err := rpHandler.Add(); err != nil {
				return FAILED, err
			}
			if err := cqHandlers.Add(); err != nil {
				return FAILED, err
			}
		case UPDATE:
			if err := cqHandlers.Update(); err != nil {
				return FAILED, err
			}
		case DEL:
			if err := cqHandlers.Del(); err != nil {
				return FAILED, err
			}
			if err := rpHandler.Del(); err != nil {
				return FAILED, err
			}
		case MOD:
			if err := rpHandler.Mod(); err != nil {
				return FAILED, err
			}
		case SHOW:
			ret += rpHandler.Show()
			ret += cqHandlers.Show()
		default:
			return FAILED, fmt.Errorf("Invilid rp action %d", c.action)
		}
	}
	return ret, nil
}

func (r *RPHandler) Add() error {
	log.Infof("add retention policy db(%s) rp(%s) duration=%dh shard duration=%dh", r.db, r.rp, r.duration, r.shardDuration)
	dbs := getCurrentDBs(r.client)
	if !dbs[r.db] {
		if err := createDB(r.client, r.db); err != nil {
			return err
		}
	}
	defaultFlag := false
	if r.rp == RP_1M {
		defaultFlag = true
	}
	RP := &RetentionPolicy{
		name:          r.rp,
		duration:      fmt.Sprintf("%dh", r.duration),
		shardDuration: fmt.Sprintf("%dh", r.shardDuration),
		defaultFlag:   defaultFlag,
	}
	if retentionPolicyExists(r.client, r.db, r.rp) {
		return fmt.Errorf("rp(%s) already exist", r.rp)
	} else {
		return createRetentionPolicy(r.client, r.db, RP)
	}
}

func (r *RPHandler) Mod() error {
	log.Infof("mod retention policy db(%s) rp(%s) duration=%dh", r.db, r.rp, r.duration)
	if retentionPolicyExists(r.client, r.db, r.rp) {
		rp := getRetentionPolicy(r.client, r.db, r.rp)
		if rp == nil {
			return fmt.Errorf("get db(%s) retention policy(%s) failed", r.db, r.rp)
		}
		// 如果修改后的duration小于shard duration，则将shard duration修改为duration
		var hour int
		fmt.Sscanf(rp.shardDuration, "%dh", &hour)
		if hour > r.duration {
			newrp := &RetentionPolicy{
				name:          r.rp,
				duration:      fmt.Sprintf("%dh", r.duration),
				shardDuration: fmt.Sprintf("%dh", r.duration),
			}
			return alterRetentionPolicy(r.client, r.db, newrp)
		}
		return alterRetentionPolicyDuration(r.client, r.db, r.rp, fmt.Sprintf("%dh", r.duration))
	} else {
		if r.rp == RP_1M || r.rp == RP_1S {
			log.Infof("create and mod retention policy db(%s) rp(%s) duration=%dh", r.db, r.rp, r.duration)
			dbs := getCurrentDBs(r.client)
			if !dbs[r.db] {
				if err := createDB(r.client, r.db); err != nil {
					return err
				}
			}
			if err := createDefaultRPIfNotExist(r.client, r.db, r.rp); err != nil {
				return err
			}
			return r.Mod()
		}
		return fmt.Errorf("rp(%s) is not exist", r.rp)
	}
}

func (r *RPHandler) Del() error {
	log.Infof("del retention policy db(%s) rp(%s)", r.db, r.rp)
	cmd := fmt.Sprintf("drop retention policy %s on %s", r.rp, r.db)
	if _, err := queryResponse(r.client, r.db, r.rp, cmd); err != nil {
		return err
	}
	return nil
}

func (r *RPHandler) Show() string {
	if rows, err := queryRows(r.client, r.db, r.rp, "show retention policies"); err != nil {
		return err.Error()
	} else {
		ret := ""
		for _, row := range rows {
			ret += fmt.Sprintf("%+v\n", row)
		}
		return ret
	}
}

func createDefaultRPIfNotExist(client client.Client, db, rp string) error {
	if retentionPolicyExists(client, db, rp) {
		return nil
	}
	if rp != RP_1M && rp != RP_1S {
		return fmt.Errorf("rp(%s) is not exist", rp)
	}
	log.Infof("create default db(%s) rp(%s)", db, rp)

	defaultFlag := false
	duration := "26h"
	shardDuration := "1h"
	if rp == RP_1M {
		defaultFlag = true
		duration = "170h"
		shardDuration = "17h"
	}
	RP := &RetentionPolicy{
		name:          rp,
		duration:      duration,
		shardDuration: shardDuration,
		defaultFlag:   defaultFlag,
	}
	return createRetentionPolicy(client, db, RP)
}

func (c *CQHandler) Add() error {
	fields := getFields(c.db)
	if len(fields) == 0 {
		return fmt.Errorf("get db(%s) fields faild", c.db)
	}

	for _, field := range fields {
		cqCmd := c.genCQCommand(field)
		log.Info(cqCmd)
		if _, err := queryResponse(c.client, c.db, c.srcRP, cqCmd); err != nil {
			return err
		}
	}
	return nil
}

func isCQExist(db, cqName string, cqInfos []CQInfo) bool {
	for _, cqInfo := range cqInfos {
		if cqInfo.db == db && cqInfo.name == cqName {
			return true
		}
	}
	return false
}

func (c *CQHandler) Update() error {
	cqInfos, err := GetCQInfos(c.client)
	if err != nil {
		return err
	}
	fields := getFields(c.db)
	for _, field := range fields {
		if isCQExist(c.db, c.CQName(field), cqInfos) {
			continue
		}
		cqCmd := c.genCQCommand(field)
		log.Info(cqCmd)
		fmt.Println("new CQ: ", cqCmd)
		if _, err := queryResponse(c.client, c.db, c.srcRP, cqCmd); err != nil {
			return err
		}
	}
	return nil
}

func (c *CQHandler) CQName(field string) string {
	return "cq_" + c.dstRP + "__" + field
}

func (c *CQHandler) genCQCommand(field string) string {
	aggr := c.aggrSummable
	if unsumableFieldsMap[field] {
		aggr = c.aggrUnsummable
	}
	aggrFunc := fmt.Sprintf("%s(%s)", aggr, field)
	if aggr == AVG {
		aggrFunc = fmt.Sprintf("floor(%s(%s))", aggr, field)
	}
	return fmt.Sprintf(
		"CREATE CONTINUOUS QUERY %s ON %s "+
			"BEGIN "+
			"SELECT %s AS %s  INTO %s.%s.main FROM %s.main GROUP BY time(%s), * TZ('Asia/Shanghai')"+
			"END",
		c.CQName(field), c.db,
		aggrFunc, field, c.db, c.dstRP, c.srcRP, c.interval)
}

func (c *CQHandler) Del() error {
	fields := getFields(c.db)
	for _, field := range fields {
		cmd := fmt.Sprintf("drop continuous query %s on %s", c.CQName(field), c.db)
		log.Info(cmd)
		if _, err := queryResponse(c.client, c.db, c.dstRP, cmd); err != nil {
			return err
		}
	}

	return nil
}

func (c *CQHandler) Show() string {
	if rows, err := queryRows(c.client, c.db, c.dstRP, "show continuous queries"); err != nil {
		return err.Error()
	} else {
		ret := ""
		for _, row := range rows {
			if row.Name != c.db && row.Tags["name"] != c.db {
				continue
			}
			ret += fmt.Sprintf("%+v\n", row)
		}
		return ret
	}
	return ""
}

func createDB(httpClient client.Client, db string) error {
	log.Infof("Create database %s if not exist.", db)
	res, e := httpClient.Query(client.NewQuery(
		fmt.Sprintf("CREATE DATABASE %s", db), "", ""))
	if err := checkResponse(res, e); err != nil {
		log.Errorf("Create database %s failed, error info: %s", db, err)
		return err
	}
	return nil
}

func flatGetDBTagsInStruct(t reflect.Type) []string {
	ret := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		switch f.Type.Kind() {
		case reflect.Struct:
			ret = append(ret, flatGetDBTagsInStruct(f.Type)...)
		default:
			if v, ok := f.Tag.Lookup("db"); ok {
				ret = append(ret, v)
			}
		}
	}
	return ret
}

func containsString(array []string, str string) bool {
	for _, v := range array {
		if v == str {
			return true
		}
	}
	return false
}

func getFields(db string) []string {
	var meter zerodoc.Meter
	if strings.HasPrefix(db, zerodoc.MeterVTAPNames[zerodoc.FLOW_ID]) {
		meter = &zerodoc.FlowMeter{}
	} else if strings.HasPrefix(db, zerodoc.MeterVTAPNames[zerodoc.ACL_ID]) {
		meter = &zerodoc.UsageMeter{}
	} else {
		log.Errorf("db(%s) unsupport get fields", db)
		return nil
	}

	// 对于 latency 对应的field，需要去除sum和count后缀,并去重
	fields := flatGetDBTagsInStruct(reflect.TypeOf(meter).Elem())
	newFields := []string{}
	for _, field := range fields {
		for key, _ := range unsumableFieldsMap {
			if field == key+"_sum" {
				field = key
				break
			}
			if field == key+"_count" {
				field = ""
				break
			}
		}
		if field != "" {
			newFields = append(newFields, field)
		}
	}
	// 如果存在rawFields，则需要增加extraFields
	rawFields := []string{"byte_tx", "packet_tx", "retrans_tx", "http_client_error", "dns_client_error",
		"client_syn_repeat", "server_syn_ack_repeat", "client_establish_fail"}
	// 组合的字段，需要额外增加
	extraFields := []string{"byte", "packet", "retrans", "http_error", "dns_error",
		"client_establish_fail", "server_establish_fail", "tcp_establish_fail"}

	for i, _ := range rawFields {
		if !containsString(newFields, extraFields[i]) && containsString(newFields, rawFields[i]) {
			newFields = append(newFields, extraFields[i])
		}
	}

	return newFields
}
