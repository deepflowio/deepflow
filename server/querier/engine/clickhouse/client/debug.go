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

package client

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/google/uuid"
)

type Debug struct {
	IP        string
	Sql       string
	QueryTime string
	QueryUUID string
	Error     string
}

type DebugInfo struct {
	Debug []Debug
}

func NewDebug(sql string) *Debug {

	return &Debug{
		IP:        config.Cfg.Clickhouse.Host,
		Sql:       sql,
		QueryUUID: uuid.NewString(),
	}
}
func (s *DebugInfo) Get() map[string]interface{} {
	return map[string]interface{}{
		"query_sqls": s.Debug,
	}
}

func (s *Debug) String() string {
	return fmt.Sprintf(
		"| ip: %s | sql: %s | query_time: %s | query_uuid: %s | error: %s |",
		s.IP, s.Sql, s.QueryTime, s.QueryUUID, s.Error,
	)
}
