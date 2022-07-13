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

package reciter_api

import (
	"encoding/json"
)

type OptStatus string

const (
	OPT_STATUS_OK           OptStatus = "ok"
	OPT_STATUS_FAILED                 = "failed"
	OPT_STATUS_PARTIAL_DATA           = "partial_data"
)

type QueryResult struct {
	OptStatus   `json:"opt_status"`
	Description string `json:"description"`
	ResultData  `json:"data"`
	QueryID     uint32       `json:"query_id"`
	QueryHits   uint64       `json:"query_hits"`
	ModuleTime  []ModuleTime `json:"module_time"`
	PeerStats   []PeerStats  `json:"peer_stats"`
}

type ModuleTime struct {
	Module string `json:"module"`
	Time   string `json:"time"`
}

type PeerStats struct {
	Peer     string `json:"peer"`
	Received uint64 `json:"received"`
	Finished bool   `json:"finished"`
}

type ResultData struct {
	TagColumns   []string     `json:"tag_columns"`
	FieldColumns []string     `json:"field_columns"`
	Data         []PointGroup `json:"data"`
}

type PointGroup struct {
	Tags   []string        `json:"tags"`
	Fields [][]interface{} `json:"fields"`
}

func (q *QueryResult) FromBytes(b []byte) error {
	return json.Unmarshal(b, q)
}

func (q *QueryResult) ToBytes() ([]byte, error) {
	return json.Marshal(q)
}

func QueryResultFromBytes(b []byte) (*QueryResult, error) {
	data := &QueryResult{}
	if err := data.FromBytes(b); err != nil {
		return nil, err
	}
	return data, nil
}
