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

	"github.com/bitly/go-simplejson"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
)

func GetIcon(cfg *config.ControllerConfig) (*simplejson.Json, error) {
	errResponse, _ := simplejson.NewJson([]byte("{}"))
	if !cfg.DFWebService.Enabled {
		return errResponse, nil
	}
	body := make(map[string]interface{})
	response, err := common.CURLPerform("GET", fmt.Sprintf("http://%s:%d/v1/icons", cfg.DFWebService.Host, cfg.DFWebService.Port), body)
	if err != nil {
		log.Error(err)
		return errResponse, err
	}
	return response, err
}
