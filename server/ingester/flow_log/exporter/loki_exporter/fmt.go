package loki_exporter

import (
	"fmt"
	exporter_common "github.com/deepflowio/deepflow/server/ingester/flow_log/exporter/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"strings"
)

type LogLevel string

const (
	// https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/logs/v1/logs.proto
	LogLevelUNSPECIFIED LogLevel = "UNSPECIFIED"
	LogLevelTRACE       LogLevel = "TRACE"
	LogLevelINFO        LogLevel = "INFO"
	LogLevelDEBUG       LogLevel = "DEBUG"
	LogLevelWARN        LogLevel = "WARN"
	LogLevelERROR       LogLevel = "ERROR"
	LogLevelFATAL       LogLevel = "FATAL"
)

var defaultHeader = map[string]string{
	"time":         "time",
	"service_name": "service_name",
	"log_level":    "log_level",
	"trace_id":     "trace_id",
	"span_id":      "span_id",
}

func (le *LokiExporter) buildLogHeader() {
	defaultLogHeaderFormat := `{time}="%s",{service_name}="%s",{log_level}="%s",{trace_id}="%s",{span_id}="%s",`
	for k, v := range defaultHeader {
		if _, ok := le.cfg.LogFmt.Mapping[k]; ok {
			v = le.cfg.LogFmt.Mapping[k]
		}
		defaultLogHeaderFormat = strings.Replace(defaultLogHeaderFormat, "{"+k+"}", v, 1)
	}
	le.logHeaderFmt = defaultLogHeaderFormat
	return
}

func responseStatusToLogLevel(status uint8) LogLevel {
	switch datatype.LogMessageStatus(status) {
	case datatype.STATUS_OK:
		return LogLevelINFO
	case datatype.STATUS_CLIENT_ERROR, datatype.STATUS_SERVER_ERROR, datatype.STATUS_ERROR:
		return LogLevelERROR
	default:
		return LogLevelUNSPECIFIED
	}
}

func buildLogBodyDNS(l7 *log_data.L7FlowLog) string {
	return fmt.Sprintf(
		`request_type="%s",request_resource="%s",response_code=%d,response_exception="%s",response_result=%s`,
		l7.RequestType, l7.RequestResource, l7.ResponseCode, l7.ResponseException, l7.ResponseResult,
	)
}

func buildLogBodyHTTP(l7 *log_data.L7FlowLog) string {
	return fmt.Sprintf(
		`method="%s",name="%s",path="%s",status_code=%d,response_exception=%s`,
		l7.RequestType, l7.RequestDomain, l7.RequestResource, l7.ResponseCode, l7.ResponseException,
	)
}
func buildLogBodyDubbo(l7 *log_data.L7FlowLog) string {
	return fmt.Sprintf(
		`rpc_system="apache_dubbo",service="%s",method="%s",request_domain="%s",dubbo_version="%s",response_code=%d,response_exception=%s`,
		l7.RequestResource, l7.RequestType, l7.RequestDomain, l7.Version, l7.ResponseCode, l7.ResponseException,
	)
}
func buildLogBodyGRPC(l7 *log_data.L7FlowLog) string {
	return fmt.Sprintf(
		`rpc_system="grpc",service="%s",method="%s",request_domain="%s",http_flavor="%s",response_code=%d,response_exception=%s`,
		l7.RequestResource, l7.RequestType, l7.RequestDomain, l7.Version, l7.ResponseCode, l7.ResponseException,
	)
}

func buildLogBodyKafka(l7 *log_data.L7FlowLog) string {
	return fmt.Sprintf(
		`messaging_system="kafka",request_type="%s",request_resource="%s",request_domain="%s",response_code=%d,response_exception=%s`,
		l7.RequestType, l7.RequestResource, l7.RequestDomain, l7.ResponseCode, l7.ResponseException,
	)
}

func buildLogBodyMQTT(l7 *log_data.L7FlowLog) string {
	return fmt.Sprintf(
		`messaging_system="mqtt",request_type="%s",request_resource="%s",request_domain="%s",response_code=%d,response_exception=%s`,
		l7.RequestType, l7.RequestResource, l7.RequestDomain, l7.ResponseCode, l7.ResponseException,
	)
}

func buildLogBodyMySQL(l7 *log_data.L7FlowLog) string {
	_, operation := exporter_common.GetSQLSpanNameAndOperation(l7.RequestResource)
	return fmt.Sprintf(
		`db_system="mysql",operation="%s",statement="%s",request_type="%s",response_exception=%s`,
		operation, l7.RequestResource, l7.RequestType, l7.ResponseException,
	)
}

func buildLogBodyPostgreSQL(l7 *log_data.L7FlowLog) string {
	_, operation := exporter_common.GetSQLSpanNameAndOperation(l7.RequestResource)
	return fmt.Sprintf(
		`db_system="postgresql",operation="%s",statement="%s",request_type="%s",response_exception=%s`,
		operation, l7.RequestResource, l7.RequestType, l7.ResponseException,
	)
}

func buildLogBodyRedis(l7 *log_data.L7FlowLog) string {
	_, operation := exporter_common.GetSQLSpanNameAndOperation(l7.RequestResource)
	return fmt.Sprintf(
		`db_system="redis",operation="%s",statement="%s",request_type="%s",response_exception=%s`,
		operation, l7.RequestType, l7.RequestResource, l7.ResponseException,
	)
}
