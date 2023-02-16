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
	"time"

	"github.com/go-redis/redis/v9"
	"golang.org/x/sync/singleflight"

	dbredis "github.com/deepflowio/deepflow/server/controller/db/redis"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type Client struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    dbredis.RedisConfig
	db     redis.UniversalClient
	sf     singleflight.Group
}

func newClient(cfg dbredis.RedisConfig) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{db: dbredis.GetClient().ResourceAPI, ctx: ctx, cancel: cancel, cfg: cfg}
}

func (c *Client) Keys(pattern string) ([]string, error) {
	return c.db.Keys(c.ctx, pattern).Result()
}

func (c *Client) Get(key string) (responseData []ResponseElem, err error) {
	strCache, err := c.db.Get(c.ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return responseData, nil
	}
	if err != nil {
		log.Error(err)
		return responseData, err
	}
	err = json.Unmarshal([]byte(strCache), &responseData)
	if err != nil {
		log.Error(err)
		return responseData, err
	}
	return
}

// TODO: use singleflight to reduce the pressure on redis
func (c *Client) SingleFlightGet(key string) ([]ResponseElem, error) {
	v, err, _ := c.sf.Do(key, func() (interface{}, error) {
		return c.Get(key)
	})
	if err != nil {
		return nil, err
	}
	return v.([]ResponseElem), nil
}

func (c *Client) Set(key string, data []ResponseElem) error {
	strCache, err := json.Marshal(data)
	if err != nil {
		log.Error(err)
		return err
	}
	_, err = c.db.Set(c.ctx, key, strCache, time.Duration(c.cfg.ResourceAPIExpireInterval)*time.Second).Result()
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (c *Client) Delete(key string) error {
	_, err := c.db.Del(c.ctx, key).Result()
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (c *Client) Close() error {
	c.cancel()
	return nil
}
