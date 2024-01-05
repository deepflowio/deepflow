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

package redis

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v9"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("db.redis")
var (
	clientOnce sync.Once
	client     *Client
)

type Config struct {
	ResourceAPIDatabase       int      `default:"1" yaml:"resource_api_database"`
	ResourceAPIExpireInterval int      `default:"3600" yaml:"resource_api_expire_interval"`
	DimensionResourceDatabase int      `default:"2" yaml:"dimension_resource_database"`
	Host                      []string `default:"" yaml:"host"` // TODO add default value
	Port                      uint32   `default:"6379" yaml:"port"`
	Password                  string   `default:"deepflow" yaml:"password"`
	TimeOut                   uint32   `default:"30" yaml:"timeout"`
	Enabled                   bool     `default:"false" yaml:"enabled"`
	ClusterEnabled            bool     `default:"false" yaml:"cluster_enabled"`
}

func GetClient() *Client {
	return client
}

func GetConfig() *Config { // TODO use this function
	return client.Config
}

type Client struct {
	ResourceAPI       redis.UniversalClient
	DimensionResource redis.UniversalClient
	Config            *Config
}

func generateAddrs(cfg Config) []string {
	var addrs []string
	for i := range cfg.Host {
		addrs = append(addrs, fmt.Sprintf("%s:%d", cfg.Host[i], cfg.Port))
	}
	return addrs
}

func generateSimpleAddr(cfg Config) string {
	return generateAddrs(cfg)[0]
}

func createSimpleClient(cfg Config, database int) redis.UniversalClient {
	addr := generateSimpleAddr(cfg)
	log.Infof("redis addr: %v", addr)
	return redis.NewClient(&redis.Options{
		Addr:        addr,
		Password:    cfg.Password,
		DB:          database,
		DialTimeout: time.Duration(cfg.TimeOut) * time.Second,
	})
}

func generateClusterAddrs(cfg Config) []string {
	return generateAddrs(cfg)
}

func createClusterClient(cfg Config) redis.UniversalClient {
	addrs := generateClusterAddrs(cfg)
	log.Infof("redis addrs: %v", addrs)
	return redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:       addrs,
		Password:    cfg.Password,
		DialTimeout: time.Duration(cfg.TimeOut) * time.Second,
	})
}

func createUniversalClient(cfg Config, database int) redis.UniversalClient {
	if cfg.ClusterEnabled {
		return createClusterClient(cfg)
	} else {
		return createSimpleClient(cfg, database)
	}
}

func Init(ctx context.Context, cfg Config) (err error) {
	clientOnce.Do(func() {
		client = &Client{
			ResourceAPI:       createUniversalClient(cfg, cfg.ResourceAPIDatabase),
			DimensionResource: createUniversalClient(cfg, cfg.DimensionResourceDatabase),
		}
		_, err = client.ResourceAPI.Ping(ctx).Result()
		if err != nil {
			return
		}
		_, err = client.DimensionResource.Ping(ctx).Result()
		return
	})
	return
}
