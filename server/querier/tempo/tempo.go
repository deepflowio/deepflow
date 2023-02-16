package tempo

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"

	/* "github.com/grafana/tempo/pkg/tempopb"
	v1 "github.com/grafana/tempo/pkg/tempopb/common/v1"
	resourceProto "github.com/grafana/tempo/pkg/tempopb/resource/v1"
	traceProto "github.com/grafana/tempo/pkg/tempopb/trace/v1" */
	"github.com/deepflowio/tempopb"
	v1 "github.com/deepflowio/tempopb/common/v1"
	resourceProto "github.com/deepflowio/tempopb/resource/v1"
	traceProto "github.com/deepflowio/tempopb/trace/v1"
	"github.com/google/uuid"

	//"github.com/k0kubun/pp"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("querier.tempo")
var L7_TRACING_SERVICE_UID = "service_uid"
var L7_TRACING_SERVICE_UNAME = "service_uname"
var L7_FLOW_LOG_SERVICE_NAME = "app_service"
var L7_TRACING_ENDPOINT = "endpoint"
var L7_TRACING_OTEL_SDK_NAME = "telemetry.sdk.name"
var L7_TRACING_OTEL_SDK_VERSION = "telemetry.sdk.version"
var TABLE_NAME_L7_FLOW_LOG = "l7_flow_log"

var SEARCH_FIELDS = []string{
	"trace_id as traceID", "app_service as rootServiceName", "endpoint as rootTraceName", "toUnixTimestamp64Micro(start_time) as startTimeUnixNano", "response_duration/1000 as durationMs",
}

var SPAN_ATTRS_MAP = map[string]string{
	"service.name": L7_FLOW_LOG_SERVICE_NAME,
	"name":         L7_TRACING_ENDPOINT,
}

var RESOURCE_KEY_MAP = map[string]string{
	"service.id":   L7_TRACING_SERVICE_UID,
	"service.name": L7_TRACING_SERVICE_UNAME,
}

var SPAN_KEY_MAP = map[string]string{
	"tap_side":                "Enum(tap_side)",
	"deepflow_span_id":        "deepflow_span_id",
	"deepflow_parent_span_id": "deepflow_parent_span_id",
}

func L7TracingRequest(args *common.TempoParams) (map[string]interface{}, error) {
	url := fmt.Sprintf("http://%s:%s/v1/stats/querier/L7FlowTracing", config.Cfg.DeepflowApp.Host, config.Cfg.DeepflowApp.Port)
	l7Body := map[string]interface{}{
		"trace_id":       args.TraceId,
		"time_start":     args.StartTime,
		"time_end":       args.EndTime,
		"database":       "flow_log",
		"table":          "l7_flow_log",
		"has_attributes": 1,
	}
	jsonBytes, _ := json.Marshal(l7Body)
	payload := strings.NewReader(string(jsonBytes))
	client := &http.Client{}
	reqest, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return nil, err
	}
	reqest.Header.Add("Content-Type", "application/json")
	response, err := client.Do(reqest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("get deepflow-app l7tracing error, url: %s, body: %s, code '%d'", url, l7Body, response.StatusCode))
	}

	body, err := ParseResponse(response)
	if err != nil {
		return nil, err
	}

	_, ok := body["DATA"]
	if !ok || body["DATA"] == nil || len(body["DATA"].(map[string]interface{})) < 1 {
		return nil, nil
	}
	return body["DATA"].(map[string]interface{}), err
}

func ConvertL7TracingRespToProto(data map[string]interface{}, argTraceId string) (req *tempopb.Trace) {
	services := data["services"]
	//resources := []*resourceProto.Resource{}
	resourceUidMap := map[string]*traceProto.ResourceSpans{}
	req = &tempopb.Trace{
		Batches: []*traceProto.ResourceSpans{},
	}
	for _, s := range services.([]interface{}) {
		service, ok := s.(map[string]interface{})
		if !ok {
			//fmt.Println(s)
			continue
		}
		rs := resourceProto.Resource{}
		for k, v := range RESOURCE_KEY_MAP {
			rsAttr := v1.KeyValue{Key: k}
			value := service[v].(string)
			rsAttr.Value = &v1.AnyValue{Value: &v1.AnyValue_StringValue{StringValue: value}}
			rs.Attributes = append(rs.Attributes, &rsAttr)
		}
		if rs.Attributes == nil {
			rs.Attributes = append(rs.Attributes, &v1.KeyValue{Key: ""})
		}
		//resources = append(resources, &rs)
		rsSpans := &traceProto.ResourceSpans{Resource: &rs, InstrumentationLibrarySpans: []*traceProto.InstrumentationLibrarySpans{}}
		resourceUidMap[service[L7_TRACING_SERVICE_UID].(string)] = rsSpans
		req.Batches = append(req.Batches, rsSpans)
	}
	traces := data["tracing"]
	idMap := map[string][]byte{}
	networkParentMap := map[string]string{}
	for _, t := range traces.([]interface{}) {
		trace, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		serviceUid, ok := trace[L7_TRACING_SERVICE_UID]
		var rsSpans *traceProto.ResourceSpans

		spanId := trace["deepflow_span_id"].(string)
		parentSpanId := trace["deepflow_parent_span_id"].(string)
		if ok && serviceUid != nil {
			if rsSpans, ok = resourceUidMap[serviceUid.(string)]; !ok {
				networkParentMap[spanId] = parentSpanId
				continue
			}
		} else {
			networkParentMap[spanId] = parentSpanId
			continue
		}
		// skip network span, find parent
		for {
			if npi, ok := networkParentMap[parentSpanId]; ok {
				parentSpanId = npi
			} else {
				break
			}
		}

		var attrs map[string]interface{}
		if traceAttrs, ok := trace["attributes"]; ok && traceAttrs != nil {
			json.Unmarshal([]byte(trace["attributes"].(string)), &attrs)
		}
		otelSdkName := ""
		otelSdkVersion := ""
		sdkName, ok := attrs[L7_TRACING_OTEL_SDK_NAME]
		if ok && sdkName != nil {
			otelSdkName = sdkName.(string)
		}
		sdkVersion, ok := attrs[L7_TRACING_OTEL_SDK_VERSION]
		if ok && sdkVersion != nil {
			otelSdkVersion = sdkVersion.(string)
		}
		var ilSpan *traceProto.InstrumentationLibrarySpans
		for _, i := range rsSpans.InstrumentationLibrarySpans {
			if i.InstrumentationLibrary.Name == otelSdkName && i.InstrumentationLibrary.Version == otelSdkVersion {
				ilSpan = i
				break
			}
		}
		if ilSpan == nil {
			ilSpan = &traceProto.InstrumentationLibrarySpans{
				InstrumentationLibrary: &v1.InstrumentationLibrary{
					Name:    otelSdkName,
					Version: otelSdkVersion,
				},
				Spans: []*traceProto.Span{},
			}
			rsSpans.InstrumentationLibrarySpans = append(rsSpans.InstrumentationLibrarySpans, ilSpan)
		}
		traceId := trace["trace_id"].(string)
		if traceId == "" {
			traceId = argTraceId
		}

		spanId = strings.ReplaceAll(spanId, "0x", "")
		//spanId = strings.ReplaceAll(spanId, ".", "0")
		spanIdBytes := decodeIdBytes(spanId, 8, idMap)

		//spanIdBytes := []byte{0xab, 0xb5, 0xcf, 0x60, 0x03, 0x2b, 0xc5, 0xfe}
		parentSpanId = strings.ReplaceAll(parentSpanId, "0x", "")
		//parentSpanId = strings.ReplaceAll(parentSpanId, ".", "0")
		parentSpanIdBytes := decodeIdBytes(parentSpanId, 8, idMap)
		traceId = strings.ReplaceAll(traceId, "-", "")
		traceIdBytes := decodeIdBytes(traceId, 16, idMap)

		spanName := trace["endpoint"].(string)
		if spanName == "" {
			spanName = trace["request_resource"].(string)
		}
		span := &traceProto.Span{
			//TraceId:           []byte(traceId),
			TraceId:           traceIdBytes,
			SpanId:            spanIdBytes,
			ParentSpanId:      parentSpanIdBytes,
			StartTimeUnixNano: uint64(trace["start_time_us"].(float64)) * 1000,
			EndTimeUnixNano:   uint64(trace["end_time_us"].(float64)) * 1000,
			Name:              spanName,
			Attributes:        []*v1.KeyValue{},
			Status:            &traceProto.Status{},
			//DroppedAttributesCount: 1,
		}
		for k, v := range attrs {
			span.Attributes = append(span.Attributes, &v1.KeyValue{
				Key:   k,
				Value: &v1.AnyValue{Value: &v1.AnyValue_StringValue{StringValue: v.(string)}},
			})
		}
		for k, v := range SPAN_KEY_MAP {
			_, ok := trace[v]
			value := ""
			if ok {
				value = trace[v].(string)
			}
			span.Attributes = append(span.Attributes, &v1.KeyValue{
				Key:   k,
				Value: &v1.AnyValue{Value: &v1.AnyValue_StringValue{StringValue: value}},
			})
		}
		ilSpan.Spans = append(ilSpan.Spans, span)
	}
	//pp.Println(req)
	return req
}

func FindTraceByTraceID(args *common.TempoParams) (req *tempopb.Trace, err error) {
	//return xxx(), err
	data, err := L7TracingRequest(args)
	if err != nil {
		return req, err
	}
	if data == nil {
		return req, nil
	}
	req = ConvertL7TracingRespToProto(data, args.TraceId)
	return req, nil
}

func ParseResponse(response *http.Response) (map[string]interface{}, error) {
	var result map[string]interface{}
	body, err := ioutil.ReadAll(response.Body)
	if err == nil {
		err = json.Unmarshal(body, &result)
	}
	return result, err
}

func ShowTags(args *common.TempoParams) (resp map[string][]interface{}, debug map[string]interface{}, err error) {
	sql := fmt.Sprintf("show tags from %s", TABLE_NAME_L7_FLOW_LOG)
	query_uuid := uuid.New()
	querierArgs := common.QuerierParams{
		DB:         "flow_log",
		Sql:        sql,
		DataSource: "",
		Debug:      args.Debug,
		QueryUUID:  query_uuid.String(),
		Context:    args.Context,
	}
	ckEngine := &clickhouse.CHEngine{DB: querierArgs.DB, DataSource: querierArgs.DataSource}
	ckEngine.Init()
	result, debug, err := ckEngine.ExecuteQuery(&querierArgs)
	if err != nil {
		// TODO
		log.Errorf("%v %v", debug, err)
		return nil, debug, err
	}
	tagNames := []interface{}{}
	for _, d := range result.Values {
		value := d.([]interface{})
		if strings.Contains(value[0].(string), "attribute.") {
			tagNames = append(tagNames, value[0])
		}

	}
	resp = map[string][]interface{}{
		"tagNames": tagNames,
	}
	return resp, debug, err
}

func ShowTagValues(args *common.TempoParams) (resp map[string][]interface{}, debug map[string]interface{}, err error) {
	tagName, ok := SPAN_ATTRS_MAP[args.TagName]
	if !ok {
		tagName = args.TagName
	}
	sql := fmt.Sprintf("show tag %s values from %s", tagName, TABLE_NAME_L7_FLOW_LOG)
	query_uuid := uuid.New()
	querierArgs := common.QuerierParams{
		DB:         "flow_log",
		Sql:        sql,
		DataSource: "",
		Debug:      args.Debug,
		QueryUUID:  query_uuid.String(),
		Context:    args.Context,
	}
	ckEngine := &clickhouse.CHEngine{DB: querierArgs.DB, DataSource: querierArgs.DataSource}
	ckEngine.Init()
	result, debug, err := ckEngine.ExecuteQuery(&querierArgs)
	if err != nil {
		// TODO
		log.Errorf("%v %v", debug, err)
		return nil, debug, err
	}
	tagValues := []interface{}{}
	for _, d := range result.Values {
		value := d.([]interface{})
		tagValues = append(tagValues, value[0])
	}
	resp = map[string][]interface{}{
		"tagValues": tagValues,
	}
	return resp, debug, err
}

func TraceSearch(args *common.TempoParams) (resp map[string]interface{}, debug map[string]interface{}, err error) {
	resp = map[string]interface{}{
		"metrics": map[string]interface{}{
			/* 			"inspectedBlocks": 1,
			   			"inspectedBytes":  "339664",
			   			"inspectedTraces": 20,
			   			"totalBlockBytes": "3051464", */
		},
		"traces": []map[string]interface{}{},
	}
	sql := fmt.Sprintf("select %s from %s", strings.Join(SEARCH_FIELDS, ", "), TABLE_NAME_L7_FLOW_LOG)
	filters := []string{"trace_id != ''"}
	if args.StartTime != "" {
		filters = append(filters, fmt.Sprintf("time>=%s", args.StartTime))
	}
	if args.EndTime != "" {
		filters = append(filters, fmt.Sprintf("time<=%s", args.EndTime))
	}
	for _, kv := range args.Filters {
		key := kv.Key
		if k, ok := SPAN_ATTRS_MAP[kv.Key]; ok {
			key = k
		}
		filters = append(filters, fmt.Sprintf("%s='%s'", key, kv.Value))
	}
	if args.MinDuration != "" {
		minDuration, err := time.ParseDuration(args.MinDuration)
		if err != nil {
			return nil, nil, err
		}
		filters = append(filters, fmt.Sprintf("response_duration>=%s", strconv.FormatInt(minDuration.Microseconds(), 10)))
	}
	if args.MaxDuration != "" {
		MaxDuration, err := time.ParseDuration(args.MaxDuration)
		if err != nil {
			return nil, nil, err
		}
		filters = append(filters, fmt.Sprintf("response_duration<=%s", strconv.FormatInt(MaxDuration.Microseconds(), 10)))
	}
	if filters != nil {
		where := strings.Join(filters, " AND ")
		sql = fmt.Sprintf("%s WHERE %s", sql, where)
	}
	sql = fmt.Sprintf("%s ORDER BY startTimeUnixNano desc", sql)
	if args.Limit != "" {
		sql = fmt.Sprintf("%s LIMIT %s", sql, args.Limit)
	}

	query_uuid := uuid.New()
	querierArgs := common.QuerierParams{
		DB:         "flow_log",
		Sql:        sql,
		DataSource: "",
		Debug:      "false",
		QueryUUID:  query_uuid.String(),
		Context:    args.Context,
	}
	ckEngine := &clickhouse.CHEngine{DB: querierArgs.DB, DataSource: querierArgs.DataSource}
	ckEngine.Init()
	//fmt.Println(sql)
	result, debug, err := ckEngine.ExecuteQuery(&querierArgs)
	if err != nil {
		// TODO
		//log.Errorf("%v %v", debug, err)
		return nil, debug, err
	}
	respValues := []map[string]interface{}{}
	for _, d := range result.Values {
		value := d.([]interface{})
		respValues = append(respValues, map[string]interface{}{
			"durationMs":        value[4],
			"rootServiceName":   value[1],
			"rootTraceName":     value[2],
			"startTimeUnixNano": strconv.Itoa(value[3].(int) * 1000),
			"traceID":           value[0],
		})
	}
	resp["traces"] = respValues
	return resp, debug, err
}

func decodeIdBytes(id string, length int, idMap map[string][]byte) []byte {
	idBytes := []byte{}
	if len(id) == length*2 {
		idBytes, _ = hex.DecodeString(id)
		if len(idBytes) != length {
			log.Errorf("traceId(%s) Decode Error", id)
		}
	}
	if len(idBytes) != length {
		log.Warningf("traceId(%s) length Error", id)
		if ib, ok := idMap[id]; ok {
			idBytes = ib
		} else {
			randIdBytes := make([]byte, length)
			rand.Read(randIdBytes[:])
			idMap[id] = randIdBytes
			return randIdBytes
		}
	}
	return idBytes
}
