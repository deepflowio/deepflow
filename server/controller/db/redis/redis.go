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

package redis

import (
	"fmt"
	"time"

	"github.com/go-redis/redis"
)

var RedisDB redis.UniversalClient

type RedisConfig struct {
	DimensionResourceDatabase int      `default:"2" yaml:"dimension_resource_database"`
	Host                      []string `default:"" yaml:"host"` // TODO add default value
	Port                      uint32   `default:"6379" yaml:"port"`
	Password                  string   `default:"deepflow" yaml:"password"`
	TimeOut                   uint32   `default:"30" yaml:"timeout"`
	Enabled                   bool     `default:"false" yaml:"enabled"`
}

func createUniversalRedisClient(cfg RedisConfig) redis.UniversalClient {
	var addrs []string
	for i := range cfg.Host {
		addrs = append(addrs, fmt.Sprintf("%s:%d", cfg.Host[i], cfg.Port))
	}
	return redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:       addrs,
		Password:    cfg.Password,
		DB:          cfg.DimensionResourceDatabase,
		DialTimeout: time.Duration(cfg.TimeOut) * time.Second,
	})
}

func InitRedis(cfg RedisConfig) (err error) {
	RedisDB = createUniversalRedisClient(cfg)
	_, err = RedisDB.Ping().Result()
	return
}
