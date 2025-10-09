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

package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (a *Aws) getRedisInstances(region string) ([]model.RedisInstance, error) {
	log.Debug("get redis instances starting", logger.NewORGPrefix(a.orgID))
	var rediss []model.RedisInstance

	redisClientConfig, err := config.LoadDefaultConfig(context.TODO(), a.credential, config.WithRegion(region), config.WithHTTPClient(a.httpClient))
	if err != nil {
		log.Error("client config failed (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
		return []model.RedisInstance{}, err
	}

	var retRedis []types.ServerlessCache
	var nextToken string
	var maxResults int32 = 100
	for {
		var input *elasticache.DescribeServerlessCachesInput
		if nextToken == "" {
			input = &elasticache.DescribeServerlessCachesInput{MaxResults: &maxResults}
		} else {
			input = &elasticache.DescribeServerlessCachesInput{MaxResults: &maxResults, NextToken: &nextToken}
		}
		result, err := elasticache.NewFromConfig(redisClientConfig).DescribeServerlessCaches(context.TODO(), input)
		if err != nil {
			log.Errorf("redis request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
			return []model.RedisInstance{}, err
		}
		retRedis = append(retRedis, result.ServerlessCaches...)
		if result.NextToken == nil {
			break
		}
		nextToken = *result.NextToken
	}
	for _, redis := range retRedis {
		redisName := a.getStringPointerValue(redis.ServerlessCacheName)
		redisLcuuid := common.GetUUIDByOrgID(a.orgID, redisName)
		var redisState int
		if a.getStringPointerValue(redis.Status) == "available" {
			redisState = common.REDIS_STATE_RUNNING
		}
		var vpcLcuuid string
		var azLcuuid string
		for _, subnetID := range redis.SubnetIds {
			nets, ok := a.subnetIDToVPCAZLcuuid[subnetID]
			if ok {
				vpcLcuuid = nets[0]
				azLcuuid = nets[1]
				break
			}

		}
		if vpcLcuuid == "" || azLcuuid == "" {
			log.Infof("redis instance (%s) vpc or az not found, subnet IDs: %v", redisName, redis.SubnetIds, logger.NewORGPrefix(a.orgID))
			continue
		}
		rediss = append(rediss, model.RedisInstance{
			Lcuuid:       redisLcuuid,
			Name:         redisName,
			Label:        redisName,
			State:        redisState,
			Version:      "Redis " + a.getStringPointerValue(redis.FullEngineVersion),
			AZLcuuid:     azLcuuid,
			VPCLcuuid:    vpcLcuuid,
			RegionLcuuid: a.regionLcuuid,
		})
		a.azLcuuidMap[azLcuuid] = 0
	}
	log.Debug("get redis instances complete", logger.NewORGPrefix(a.orgID))
	return rediss, nil
}
