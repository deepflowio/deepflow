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
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/go-redis/redis/v9"
	"golang.org/x/sync/singleflight"

	dbredis "github.com/deepflowio/deepflow/server/controller/db/redis"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

var (
	cliOnce sync.Once
	cli     *client
)

type client struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    dbredis.Config
	db     redis.UniversalClient
	sf     singleflight.Group
}

func getClient(cfg dbredis.Config) *client {
	cliOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cli = &client{
			db:  dbredis.GetClient().ResourceAPI,
			ctx: ctx, cancel: cancel, cfg: cfg}
	})
	return cli
}

func (c *client) keys(pattern string) ([]string, error) {
	return c.db.Keys(c.ctx, pattern).Result()
}

func (c *client) get(key string) ([]common.ResponseElem, error) {
	var result []common.ResponseElem
	strCache, err := c.db.Get(c.ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	err = json.Unmarshal([]byte(strCache), &result)
	return result, err
}

func (c *client) set(key string, data []common.ResponseElem) error {
	log.Infof("redis set data, key: %s", key)
	strCache, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = c.db.Set(c.ctx, key, strCache, time.Duration(c.cfg.ResourceAPIExpireInterval)*time.Second).Result()
	return err
}

func (c *client) delete(key string) error {
	_, err := c.db.Del(c.ctx, key).Result()
	return err
}

func (c *client) close() error {
	c.cancel()
	return nil
}
