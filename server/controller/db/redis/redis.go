package redis

import (
	"fmt"
	"github.com/go-redis/redis"
	"time"
)

var Redisdb *redis.Client

type RedisConfig struct {
	DimensionResourceDatabase int    `default:"2" yaml:"dimension_resource_database"`
	Host                      string `default:"redis" yaml:"host"`
	Port                      uint32 `default:"6379" yaml:"port"`
	Password                  string `default:"******" yaml:"password"`
	TimeOut                   uint32 `default:"30" yaml:"timeout"`
}

func InitRedis(cfg RedisConfig) (err error) {
	Redisdb = redis.NewClient(&redis.Options{
		Addr:        fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:    cfg.Password,
		DB:          cfg.DimensionResourceDatabase,
		DialTimeout: time.Duration(cfg.TimeOut) * time.Second,
	})
	_, err = Redisdb.Ping().Result()
	return
}
