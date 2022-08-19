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

package tencent

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/op/go-logging"
	tcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	thttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

var log = logging.MustGetLogger("cloud.tencent")

const (
	FINANCE_REGION_PROFILE = "金融"
	TENCENT_ENDPOINT       = ".tencentcloudapi.com"
)

type Tencent struct {
	lcuuid         string
	uuidGenerate   string
	regionName     string
	regionUuid     string
	includeRegions []string
	excludeRegions []string
	credential     *tcommon.Credential
	regionList     []tencentRegion
}

type tencentRegion struct {
	finance    bool
	name       string
	lcuuid     string
	regionName string
}

func NewTencentTce(domain mysql.Domain) (*Tencent, error) {
	config, err := simplejson.NewJson([]byte(domain.Config))
	if err != nil {
		log.Error(err)
		return nil, err
	}

	regionName, err := config.Get("region_name").String()
	if err != nil {
		log.Error("region_name must be specified")
		return nil, err
	}

	secretID, err := config.Get("secret_id").String()
	if err != nil {
		log.Error("secret_id must be specified")
		return nil, err
	}

	secretKey, err := config.Get("secret_key").String()
	if err != nil {
		log.Error("secret_key must be specified")
		return nil, err
	}

	decryptSecretKey, err := common.DecryptSecretKey(secretKey)
	if err != nil {
		log.Error("decrypt secret_key failed (%s)", err.Error())
		return nil, err
	}

	excludeRegionsStr := config.Get("exclude_regions").MustString()
	excludeRegions := []string{}
	if excludeRegionsStr != "" {
		excludeRegions = strings.Split(excludeRegionsStr, ",")
	}

	sort.Strings(excludeRegions)
	includeRegionsStr := config.Get("include_regions").MustString()
	includeRegions := []string{}
	if includeRegionsStr != "" {
		includeRegions = strings.Split(includeRegionsStr, ",")
	}
	sort.Strings(includeRegions)

	return &Tencent{
		// TODO: display_name后期需要修改为uuid_generate
		lcuuid:         domain.Lcuuid,
		uuidGenerate:   domain.DisplayName,
		regionName:     regionName,
		regionUuid:     config.Get("region_uuid").MustString(),
		excludeRegions: excludeRegions,
		includeRegions: includeRegions,
		credential:     tcommon.NewCredential(secretID, decryptSecretKey),

		// 以下属性为获取资源所用的关联关系
		regionList: []tencentRegion{},
	}, nil
}

func (t *Tencent) CheckAuth() error {
	// TODO: 更新验证
	return nil
}

func (t *Tencent) getResponse(service, version, action, regionName, resultKey string, pages bool, params map[string]interface{}, filters ...map[string]interface{}) ([]*simplejson.Json, error) {
	var responses []*simplejson.Json
	var err error
	offset, limit := 0, 100
	// simple config
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = service + ".tencentcloudapi.com"
	cpf.HttpProfile.ReqMethod = "POST"
	cpf.NetworkFailureMaxRetries = 3
	cpf.NetworkFailureRetryDuration = profile.ExponentialBackoff
	// create common client
	client := tcommon.NewCommonClient(t.credential, regionName, cpf)

	// create common request
	request := thttp.NewCommonRequest(service, version, action)

	// SetActionParameters
	body := map[string]interface{}{}
	for pKey, pValue := range params {
		body[pKey] = pValue
	}
	if len(filters) > 0 {
		// filters example:
		// body["Filters"] = []map[string]interface{}{
		// 	{
		// 		"Name":   "service-template-group-id",
		// 		"Values": []string{"ppmg-e6dy460g"},
		// 	},
		// }
		body["Filters"] = filters
	}

	for {
		if pages {
			body["Limit"] = limit
			body["Offset"] = offset
		}

		// set action request params
		err = request.SetActionParameters(body)
		if err != nil {
			return []*simplejson.Json{}, err
		}

		// create common response
		response := thttp.NewCommonResponse()

		// do request
		err = client.Send(request, response)
		if err != nil {
			return []*simplejson.Json{}, err
		}

		respJson, err := simplejson.NewJson(request.GetBody())
		if err != nil {
			return []*simplejson.Json{}, err
		}

		resultSet, ok := respJson.Get("Response").CheckGet(resultKey)
		if !ok {
			errMsg := fmt.Sprintf("request tencent action (%s) exception: not found result key (%s)", action, resultKey)
			return []*simplejson.Json{}, errors.New(errMsg)
		}

		for r := range resultSet.MustArray() {
			responses = append(responses, resultSet.GetIndex(r))
		}

		totalCount := respJson.Get("Response").Get("TotalCount").MustInt()
		if pages || totalCount < limit {
			log.Debugf("request tencent action (%s): total count is (%v)", action, limit+totalCount)
			break
		}

		offset += 100
	}

	return responses, nil
}

func (t *Tencent) checkRequiredAttributes(json *simplejson.Json, attributes []string) bool {
	for _, attribute := range attributes {
		if _, ok := json.CheckGet(attribute); !ok {
			log.Warningf("get attribute (%s) failed", attribute)
			return false
		}
	}
	return true
}

func (t *Tencent) GetCloudData() (model.Resource, error) {
	var resource model.Resource
	// 任务循环执行的是同一个实例，所以这里要对关联关系进行初始化
	t.regionList = []tencentRegion{}

	regions, err := t.getRegions()
	if err != nil {
		return model.Resource{}, err
	}
	resource.Regions = regions
	for _, region := range t.regionList {
		log.Infof("region (%s) collect starting", region.name)
		log.Infof("region (%s) collect complete", region.name)
	}

	return resource, nil
}
