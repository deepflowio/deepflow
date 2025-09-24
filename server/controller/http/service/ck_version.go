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

package service

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/querier/config"
)

func GetCKVersion() (string, error) {
	ckVersion := ""

	body := url.Values{
		"sql": {"SELECT version()"},
	}
	url := fmt.Sprintf("http://localhost:%d/v1/query?simple_sql=true", config.Cfg.ListenPort)
	resp, err := common.CURLForm(
		http.MethodPost,
		url,
		body,
	)
	if err != nil {
		log.Error(err)
		return ckVersion, err
	}
	values := resp.Get("result").Get("values").MustArray()
	if len(values) == 0 || len(values[0].([]interface{})) == 0 {
		err = fmt.Errorf("get clickhouse version failed: empty result")
		log.Error(err)
		return ckVersion, err
	}
	if row, ok := values[0].([]interface{}); ok && len(row) > 0 {
		if version, ok := row[0].(string); ok {
			ckVersion = version
		} else {
			return ckVersion, fmt.Errorf("version is not string type")
		}
	} else {
		return ckVersion, fmt.Errorf("invalid response format")
	}
	return ckVersion, err
}
