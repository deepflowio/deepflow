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

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type dataGeneratorModel interface {
	metadbmodel.AZ | metadbmodel.Host | metadbmodel.VM | metadbmodel.VPC | metadbmodel.Network | metadbmodel.VRouter |
		metadbmodel.DHCPPort | metadbmodel.NATGateway | metadbmodel.LB | metadbmodel.RDSInstance | metadbmodel.RedisInstance |
		metadbmodel.PodCluster | metadbmodel.PodNode | metadbmodel.PodNamespace | metadbmodel.PodIngress | metadbmodel.PodService |
		metadbmodel.PodGroup | metadbmodel.PodReplicaSet | metadbmodel.Pod | healerProcess | metadbmodel.CustomService |

		healerChDevice | metadbmodel.ChAZ | metadbmodel.ChChost | metadbmodel.ChVPC | metadbmodel.ChNetwork | metadbmodel.ChLBListener |
		metadbmodel.ChPodCluster | metadbmodel.ChPodNode | metadbmodel.ChPodNamespace | metadbmodel.ChPodIngress | metadbmodel.ChPodService |
		metadbmodel.ChPodGroup | metadbmodel.ChPod | metadbmodel.ChGProcess |
		metadbmodel.ChPodServiceK8sLabels | metadbmodel.ChPodServiceK8sLabel | metadbmodel.ChPodServiceK8sAnnotation | metadbmodel.ChPodServiceK8sAnnotations |
		metadbmodel.ChPodNSCloudTags | metadbmodel.ChChostCloudTags | metadbmodel.ChPodNSCloudTag | metadbmodel.ChChostCloudTag |
		metadbmodel.ChPodK8sAnnotation | metadbmodel.ChPodK8sAnnotations | metadbmodel.ChPodK8sEnv | metadbmodel.ChPodK8sEnvs | metadbmodel.ChPodK8sLabel |
		metadbmodel.ChPodK8sLabels

	GetID() int
	GetUpdatedAt() time.Time
}

type healerChDevice struct {
	metadbmodel.ChDevice
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
	metadbmodel.Process
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
