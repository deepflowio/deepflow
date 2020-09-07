package store

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/influxdata/influxdb/client/v2"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
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
	"rtt":        true,
	"rtt_client": true,
	"rtt_server": true,
	"srt":        true,
	"art":        true,
	"http_rrt":   true,
	"dns_rrt":    true,
}

type ActionEnum uint8

const (
	ADD ActionEnum = iota
	DEL
	MOD
	SHOW
)

var actionsMap = map[string]ActionEnum{
	"add":  ADD,
	"del":  DEL,
	"mod":  MOD,
	"show": SHOW,
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
	client        client.Client
	db            string
	srcRP         string
	dstRP         string
	internal      string // 分钟 <xx>m
	aggrSumable   AggrEnum
	aggrUnsumable AggrEnum
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
	if actionEnum == ADD {
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
			return nil, fmt.Errorf("CQ internal(%d) must bigger than 0. ", CQInterval)
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
			client:        httpClient,
			db:            db,
			srcRP:         baseRP,
			dstRP:         newRP,
			internal:      fmt.Sprintf("%dm", CQInterval),
			aggrSumable:   aggrsMap[aggrSummable],
			aggrUnsumable: aggrsMap[aggrUnsummable],
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

func (c *CQHandler) CQName(field string) string {
	return "cq_" + c.dstRP + "__" + field
}

func (c *CQHandler) genCQCommand(field string) string {
	aggr := c.aggrSumable
	if unsumableFieldsMap[field] {
		aggr = c.aggrUnsumable
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
		aggrFunc, field, c.db, c.dstRP, c.srcRP, c.internal)
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
	log.Infof("database %s no exists, create database now.", db)
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
	var meter app.Meter
	if strings.HasPrefix(db, zerodoc.MeterVTAPNames[zerodoc.FLOW_ID]) {
		meter = &zerodoc.FlowMeter{}
	} else if strings.HasPrefix(db, zerodoc.MeterVTAPNames[zerodoc.GEO_ID]) {
		meter = &zerodoc.GeoMeter{}
	} else if strings.HasPrefix(db, zerodoc.MeterVTAPNames[zerodoc.PACKET_ID]) {
		meter = &zerodoc.VTAPUsageMeter{}
	} else {
		log.Errorf("db(%s) unsuppor get fields", db)
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
	// 如果有 byte_tx,而没有byte，需要加上byte
	if !containsString(newFields, "byte") && containsString(newFields, "byte_tx") {
		newFields = append(newFields, "byte")
	}
	// 如果有 packet_tx,而没有packet，需要加上packet
	if !containsString(newFields, "packet") && containsString(newFields, "packet_tx") {
		newFields = append(newFields, "packet")
	}
	// 如果有 retrans_tx,而没有retrans，需要加上retrans
	if !containsString(newFields, "retrans") && containsString(newFields, "retrans_tx") {
		newFields = append(newFields, "retrans")
	}

	return newFields
}
