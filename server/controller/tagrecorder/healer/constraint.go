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

	metadbModel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type dataGeneratorModel interface {
	metadbModel.AZ | metadbModel.Host | metadbModel.VM | metadbModel.VPC | metadbModel.Network | metadbModel.VRouter |
		metadbModel.DHCPPort | metadbModel.NATGateway | metadbModel.LB | metadbModel.RDSInstance | metadbModel.RedisInstance |
		metadbModel.PodCluster | metadbModel.PodNode | metadbModel.PodNamespace | metadbModel.PodIngress | metadbModel.PodService |
		metadbModel.PodGroup | metadbModel.PodReplicaSet | metadbModel.Pod | healerProcess | metadbModel.CustomService |

		healerChDevice | metadbModel.ChAZ | metadbModel.ChChost | metadbModel.ChVPC | metadbModel.ChNetwork | metadbModel.ChLBListener |
		metadbModel.ChPodCluster | metadbModel.ChPodNode | metadbModel.ChPodNamespace | metadbModel.ChPodIngress | metadbModel.ChPodService |
		metadbModel.ChPodGroup | metadbModel.ChPod | metadbModel.ChGProcess |
		metadbModel.ChPodServiceK8sLabels | metadbModel.ChPodServiceK8sLabel | metadbModel.ChPodServiceK8sAnnotation | metadbModel.ChPodServiceK8sAnnotations |
		metadbModel.ChPodNSCloudTags | metadbModel.ChChostCloudTags | metadbModel.ChPodNSCloudTag | metadbModel.ChChostCloudTag |
		metadbModel.ChPodK8sAnnotation | metadbModel.ChPodK8sAnnotations | metadbModel.ChPodK8sEnv | metadbModel.ChPodK8sEnvs | metadbModel.ChPodK8sLabel |
		metadbModel.ChPodK8sLabels | metadbModel.ChBizService

	GetID() int
	GetUpdatedAt() time.Time
}

type healerChDevice struct {
	metadbModel.ChDevice
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
	metadbModel.Process
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
