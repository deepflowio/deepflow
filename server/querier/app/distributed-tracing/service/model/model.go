package model

import "context"

type TraceMap struct {
	QueryCondition string `json:"query_condition"`
	TimeStart      int    `json:"time_start" binding:"required"`
	TimeEnd        int    `json:"time_end" binding:"required"`
	Debug          bool   `json:"debug"`
	Context        context.Context
	OrgID          string
}

type Debug struct {
	IP        string `json:"ip"`
	Sql       string `json:"sql"`
	SqlCH     string `json:"sql_CH"`
	QueryTime string `json:"query_time"`
	QueryUUID string `json:"query_uuid"`
	Error     string `json:"error"`
}

type TraceMapDebug struct {
	QuerierDebug []Debug `json:"querier_debug"`
	FormatTime   string  `json:"format_time"`
}

type TraceMapTree struct {
}
