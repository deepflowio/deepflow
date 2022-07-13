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

package client

import (
	"fmt"
)

type Debug struct {
	IP        string
	Sql       string
	QueryTime int64
	QueryUUID string
	Error     string
}

func (s *Debug) Get() map[string]interface{} {
	return map[string]interface{}{
		"ip":         s.IP,
		"sql":        s.Sql,
		"query_time": fmt.Sprintf("%.9fs", float64(s.QueryTime)/1e9),
		"query_uuid": s.QueryUUID,
		"error":      s.Error,
	}
}

func (s *Debug) String() string {
	return fmt.Sprintf(
		"| ip: %s | sql: %s | query_time: %.9fs | query_uuid: %s | error: %s |",
		s.IP, s.Sql, float64(s.QueryTime)/1e9, s.QueryUUID, s.Error,
	)
}
