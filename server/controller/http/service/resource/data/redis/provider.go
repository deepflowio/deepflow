/**
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
	"strings"

	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/provider"
)

var log = logging.MustGetLogger("service.resource.data.redis")

var (
	keyJoiner        = " "
	keyPrefix        = "deepflow_resource_api_"
	keyPrefixForBase = "deepflow_resource_api_base_" // deepflow_resource_api_base_<resource_type> stored all data
)

type DataProvider struct {
	resourceType string
	next         provider.DataProvider // redis provider itself does not produce data, so needs next data provider to get data. Normally is mysql data provider.

	client  *client      // redis client
	keyConv keyConvertor // redis key convertor,
	urlPath string       // redis key 中 url 的 path 部分（不包含 host 及 query），用于全局刷新时过滤出本资源相关的 key
}

// Get implements provider.DataProvider interface
func (dp *DataProvider) Get(ctx *provider.DataContext) ([]common.ResponseElem, error) {
	if !dp.client.cfg.Enabled {
		return dp.next.Get(ctx)
	}

	var data []common.ResponseElem
	key, err := dp.keyConv.dataCtxToStr(ctx)
	if err != nil {
		return data, err
	}

	data, err = dp.client.get(key)
	if err != nil || len(data) == 0 {
		data, err = dp.next.Get(ctx)
		if err != nil {
			return data, err
		}
		dp.client.set(key, data)
	}
	return data, err
}

// Refresh implements provider.DataProvider interface
func (dp *DataProvider) Refresh(dataCtx *provider.DataContext) (err error) {
	if !dp.client.cfg.Enabled {
		return nil
	}

	if dataCtx == nil {
		return dp.refreshTriggeredByRecorder() // TODO reserve
	} else {
		return dp.forceRefreshManually(dataCtx)
	}
}

func (dp *DataProvider) refreshTriggeredByRecorder() error {
	return dp.refreshAll()
}

func (dp *DataProvider) refreshAll() error {
	data, err := dp.refreshBase()
	keys, err := dp.client.keys(keyPrefix + "*")
	if err != nil {
		return err
	}
	for _, key := range keys {
		if strings.Contains(key, dp.urlPath) {
			ctx, err := dp.keyConv.strToDataCtx(key)
			if err != nil {
				log.Warningf("failed to convert redis key to data context: %s", key)
				continue
			}
			fd, err := ctx.ApplyFilters(data)
			if err != nil {
				log.Warningf("failed to apply filters: %s", err)
				continue
			}
			if err = dp.client.set(key, fd); err != nil {
				log.Warningf("failed to set key %s: %s", key, err)
				continue
			}
		}
	}
	return nil
}

func (dp *DataProvider) forceRefreshManually(ctx *provider.DataContext) error {
	dp.refreshBase()
	return dp.Delete(ctx)
}

func (dp *DataProvider) refreshBase() ([]common.ResponseElem, error) {
	data, err := dp.next.Get(nil)
	if err != nil {
		return nil, err
	}
	err = dp.client.set(keyPrefixForBase+dp.resourceType, data)
	return data, err
}

// Delete is triggered by create/update/delete operation
func (dp *DataProvider) Delete(ctx *provider.DataContext) error {
	key, err := dp.keyConv.dataCtxToStr(ctx)
	if err != nil {
		return err
	}
	return dp.client.delete(key + "*")
}
