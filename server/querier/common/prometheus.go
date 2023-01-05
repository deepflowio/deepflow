package common

import (
	"context"
	"github.com/prometheus/prometheus/promql/parser"
	//"strings"
)

type PromQueryParams struct {
	MetricsWithPrefix string
	Promql            string
	StartTime         string
	EndTime           string
	Step              string
	Matchers          []string
	Context           context.Context
}

type PromQueryData struct {
	ResultType parser.ValueType `json:"resultType"`
	Result     parser.Value     `json:"result"`
}

type PromQueryResponse struct {
	Status    string      `json:"status"`
	Data      interface{} `json:"data,omitempty"`
	ErrorType errorType   `json:"errorType,omitempty"`
	Error     string      `json:"error,omitempty"`
}

type PromMetaParams struct {
	StartTime string
	EndTime   string
	LabelName string
	Context   context.Context
}

type errorType string
