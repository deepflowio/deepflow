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

package healer

import (
	"time"

	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type dataGeneratorModel interface {
	mysqlmodel.AZ | mysqlmodel.Host | mysqlmodel.VM | mysqlmodel.VPC | mysqlmodel.Network | mysqlmodel.VRouter |
		mysqlmodel.DHCPPort | mysqlmodel.NATGateway | mysqlmodel.LB | mysqlmodel.RDSInstance | mysqlmodel.RedisInstance |
		mysqlmodel.PodCluster | mysqlmodel.PodNode | mysqlmodel.PodNamespace | mysqlmodel.PodIngress | mysqlmodel.PodService |
		mysqlmodel.PodGroup | mysqlmodel.PodReplicaSet | mysqlmodel.Pod | healerProcess | mysqlmodel.CustomService |

		healerChDevice | mysqlmodel.ChAZ | mysqlmodel.ChChost | mysqlmodel.ChVPC | mysqlmodel.ChNetwork | mysqlmodel.ChLBListener |
		mysqlmodel.ChPodCluster | mysqlmodel.ChPodNode | mysqlmodel.ChPodNamespace | mysqlmodel.ChPodIngress | mysqlmodel.ChPodService |
		mysqlmodel.ChPodGroup | mysqlmodel.ChPod | mysqlmodel.ChGProcess |
		mysqlmodel.ChPodServiceK8sLabels | mysqlmodel.ChPodServiceK8sLabel | mysqlmodel.ChPodServiceK8sAnnotation | mysqlmodel.ChPodServiceK8sAnnotations |
		mysqlmodel.ChPodNSCloudTags | mysqlmodel.ChChostCloudTags | mysqlmodel.ChPodNSCloudTag | mysqlmodel.ChChostCloudTag |
		mysqlmodel.ChPodK8sAnnotation | mysqlmodel.ChPodK8sAnnotations | mysqlmodel.ChPodK8sEnv | mysqlmodel.ChPodK8sEnvs | mysqlmodel.ChPodK8sLabel |
		mysqlmodel.ChPodK8sLabels

	GetID() int
	GetUpdatedAt() time.Time
}

type healerChDevice struct {
	mysqlmodel.ChDevice
}

func (h healerChDevice) GetID() int {
	return h.DeviceID
}

func (h healerChDevice) GetUpdatedAt() time.Time {
	return h.UpdatedAt
}

func (h healerChDevice) TableName() string {
	return "ch_device"
}

type healerProcess struct {
	mysqlmodel.Process
}

func (h healerProcess) GetID() int {
	return int(h.GID)
}

func (h healerProcess) GetUpdatedAt() time.Time {
	return h.UpdatedAt
}

func (h healerProcess) TableName() string {
	return "process"
}
