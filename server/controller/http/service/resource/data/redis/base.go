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
	"strings"

	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/db/redis"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/provider"
)

var log = logging.MustGetLogger("service.resource.redis")

var (
	keyJoiner        = " "
	keyPrefix        = "deepflow_resource_api_"
	keyPrefixForBase = "deepflow_resource_api_base_"
)

type DataProvider struct {
	resourceType      string
	client            *Client               // redis client
	next              provider.DataProvider // 下一个数据源，本身不会直接生成数据，而是通过下一个数据源获取数据
	keyConv           KeyConvertor          // redis key 转换器
	urlPathInRedisKey string                // redis key 中 url path 的部分，用于全局刷新时过滤出本资源相关的 key
}

func newDataProvider(resourceType string, cfg redis.RedisConfig, next provider.DataProvider, keyConv KeyConvertor) DataProvider {
	return DataProvider{
		resourceType: resourceType,
		client:       newClient(cfg),
		next:         next,
		keyConv:      keyConv,
	}
}

func (d *DataProvider) SetURLPathInRedisKey(urlPath string) {
	d.urlPathInRedisKey = urlPath
}

func (d *DataProvider) Get(ctx *provider.DataContext) ([]ResponseElem, error) {
	var data []ResponseElem
	key, err := d.keyConv.DataContextToString(ctx)
	if err != nil {
		return data, err
	}
	data, err = d.client.Get(key)
	if err != nil {
		data, err = d.next.Get(ctx)
		d.client.Set(key, data)
	}
	return data, err
}

func (d *DataProvider) Refresh(dataCtx *provider.DataContext) (err error) {
	if dataCtx == nil {
		return d.refreshAll()
	} else {
		return d.refreshByDataContext(dataCtx)
	}
}

func (d *DataProvider) refreshAll() error {
	data, err := d.refreshBase()
	keys, err := d.client.Keys(keyPrefix + "*")
	if err != nil {
		return err
	}
	for _, key := range keys {
		if strings.Contains(key, d.urlPathInRedisKey) {
			ctx, err := d.keyConv.StringToDataContext(key)
			if err != nil {
				log.Warningf("failed to convert redis key to data context: %s", key)
				continue
			}
			fd, err := ctx.ApplyFilters(data)
			if err != nil {
				log.Warningf("failed to apply filters: %s", err)
				continue
			}
			if err = d.client.Set(key, fd); err != nil {
				log.Warningf("failed to set key %s: %s", key, err)
				continue
			}
		}
	}
	return nil
}

func (d *DataProvider) refreshBase() ([]ResponseElem, error) {
	data, err := d.next.Get(nil)
	if err != nil {
		return nil, err
	}
	if err = d.client.Set(keyPrefixForBase+d.resourceType, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (d *DataProvider) refreshByDataContext(ctx *provider.DataContext) error {
	if _, err := d.refreshBase(); err != nil {
		return err
	}
	if err := d.Delete(ctx); err != nil {
		return err
	}
	return nil
}

// 增删改资源成功后调用
func (d *DataProvider) Delete(ctx *provider.DataContext) (err error) {
	key, err := d.keyConv.DataContextToString(ctx)
	err = d.client.Delete(key + "*")
	return
}
