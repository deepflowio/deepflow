/*
 * Copyright (c) 2023 Yunshan Networks
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

package redis

import (
	"net/url"
	"sync"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/mysql"
)

var (
	podRedisCacheOnce sync.Once
	podRedisCache     *Pod
)

type Pod struct {
	DataProvider
	KeyConvertorBase
}

func GetPod(cfg redis.RedisConfig) *Pod {
	podRedisCacheOnce.Do(func() {
		podRedisCache = &Pod{}
		podRedisCache.init(cfg)
	})
	return podRedisCache
}

func (d *Pod) init(cfg redis.RedisConfig) {
	d.DataProvider = newDataProvider(common.RESOURCE_TYPE_POD_EN, cfg, mysql.NewPod(), d)
	d.SetURLPathInRedisKey("/v2/pods") // TODO use const
	d.KeyConvertorBase.setURLFormatter(d)
}

func (d *Pod) formatURL(u string) (string, error) {
	url, err := url.Parse(u)
	qc := new(urlQueryConvertorBase[model.PodQueryStoredInRedis])
	obj, err := qc.strToStruct(url.RawQuery)
	url.RawQuery, err = qc.structToStr(obj)
	return url.String(), err
}

func (d *Pod) urlStrToInfoStruct(u string) (urlInfo *model.URLInfo, err error) {
	url, err := url.Parse(u)
	qc := new(urlQueryConvertorBase[model.PodQueryStoredInRedis])
	obj, err := qc.strToStruct(url.RawQuery)
	urlInfo.RawString = url.String()
	urlInfo.UserID = obj.UserID
	urlInfo.IncludedFields = obj.IncludedFields
	urlInfo.FilterConditions = obj.PodFilterConditions.ToMapOmitEmpty()
	return
}
