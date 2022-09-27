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

// 永久删除MySQL中超过7天的软删除云平台资源数据
package recorder

import (
	"time"

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/constraint"
)

func delete[MT constraint.MySQLSoftDeleteModel](expiredAt time.Time) {
	err := mysql.Db.Unscoped().Where("deleted_at < ?", expiredAt).Delete(new(MT)).Error
	if err != nil {
		log.Errorf("mysql delete resource failed: %v", err)
	}
}

func clean(expireInterval int) {
	expiredAt := time.Now().Add(time.Duration(-expireInterval) * time.Hour)
	log.Infof("clean soft deleted resources (deleted_at < %s) started", expiredAt.Format(common.GO_BIRTHDAY))
	delete[mysql.Region](expiredAt)
	delete[mysql.AZ](expiredAt)
	delete[mysql.Host](expiredAt)
	delete[mysql.VM](expiredAt)
	delete[mysql.VPC](expiredAt)
	delete[mysql.Network](expiredAt)
	delete[mysql.VRouter](expiredAt)
	delete[mysql.DHCPPort](expiredAt)
	delete[mysql.SecurityGroup](expiredAt)
	delete[mysql.NATGateway](expiredAt)
	delete[mysql.LB](expiredAt)
	delete[mysql.LBListener](expiredAt)
	delete[mysql.CEN](expiredAt)
	delete[mysql.PeerConnection](expiredAt)
	delete[mysql.RDSInstance](expiredAt)
	delete[mysql.RedisInstance](expiredAt)
	delete[mysql.PodCluster](expiredAt)
	delete[mysql.PodNode](expiredAt)
	delete[mysql.PodNamespace](expiredAt)
	delete[mysql.PodIngress](expiredAt)
	delete[mysql.PodService](expiredAt)
	delete[mysql.PodGroup](expiredAt)
	delete[mysql.PodReplicaSet](expiredAt)
	delete[mysql.Pod](expiredAt)
	log.Info("clean soft deleted resources completed")
}

func TimedCleanDeletedResources(cleanInterval, expireInterval int) {
	// 在启动cleaner前先清理一次数据
	clean(expireInterval)
	go func() {
		for range time.Tick(time.Duration(cleanInterval) * time.Hour) {
			clean(expireInterval)
		}
	}()
}
