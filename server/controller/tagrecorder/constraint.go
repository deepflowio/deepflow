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

// tagrecorder包中使用到的泛型约束
package tagrecorder

import (
	"time"

	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

// 资源的MySQL orm对象
type MySQLChModel interface {
	mysqlmodel.ChUser | mysqlmodel.ChAlarmPolicy | mysqlmodel.ChPrometheusTargetLabelLayout | mysqlmodel.ChTargetLabel | mysqlmodel.ChAPPLabel | mysqlmodel.ChPrometheusMetricName | mysqlmodel.ChPrometheusLabelName |
		mysqlmodel.ChPrometheusMetricAPPLabelLayout | mysqlmodel.ChPodServiceK8sLabels | mysqlmodel.ChPodServiceK8sLabel | mysqlmodel.ChOSAppTags |
		mysqlmodel.ChOSAppTag | mysqlmodel.ChPodNSCloudTags | mysqlmodel.ChChostCloudTags | mysqlmodel.ChPodNSCloudTag | mysqlmodel.ChChostCloudTag | mysqlmodel.ChIntEnum |
		mysqlmodel.ChStringEnum | mysqlmodel.ChPodIngress | mysqlmodel.ChVTapPort | mysqlmodel.ChAZ | mysqlmodel.ChIPResource | mysqlmodel.ChPodK8sLabel |
		mysqlmodel.ChLBListener | mysqlmodel.ChRegion | mysqlmodel.ChVPC |
		mysqlmodel.ChDevice | mysqlmodel.ChIPRelation | mysqlmodel.ChPodGroup | mysqlmodel.ChNetwork | mysqlmodel.ChPod | mysqlmodel.ChPodCluster |
		mysqlmodel.ChPodNode | mysqlmodel.ChPodNamespace | mysqlmodel.ChTapType | mysqlmodel.ChVTap | mysqlmodel.ChPodK8sLabels | mysqlmodel.ChNodeType | mysqlmodel.ChGProcess | mysqlmodel.ChPodK8sAnnotation | mysqlmodel.ChPodK8sAnnotations |
		mysqlmodel.ChPodServiceK8sAnnotation | mysqlmodel.ChPodServiceK8sAnnotations |
		mysqlmodel.ChPodK8sEnv | mysqlmodel.ChPodK8sEnvs | mysqlmodel.ChPodService | mysqlmodel.ChChost | mysqlmodel.ChPolicy | mysqlmodel.ChNpbTunnel
}

type SubscriberMetaDBChModel interface {
	mysqlmodel.ChDevice | mysqlmodel.ChAZ | mysqlmodel.ChChost | mysqlmodel.ChVPC | mysqlmodel.ChNetwork | mysqlmodel.ChLBListener |
		mysqlmodel.ChPodCluster | mysqlmodel.ChPodNode | mysqlmodel.ChPodNamespace | mysqlmodel.ChPodIngress | mysqlmodel.ChPodService |
		mysqlmodel.ChPodGroup | mysqlmodel.ChPod | mysqlmodel.ChGProcess |
		mysqlmodel.ChPodServiceK8sLabels | mysqlmodel.ChPodServiceK8sLabel | mysqlmodel.ChPodServiceK8sAnnotation | mysqlmodel.ChPodServiceK8sAnnotations |
		mysqlmodel.ChPodNSCloudTags | mysqlmodel.ChChostCloudTags | mysqlmodel.ChPodNSCloudTag | mysqlmodel.ChChostCloudTag |
		mysqlmodel.ChPodK8sAnnotation | mysqlmodel.ChPodK8sAnnotations | mysqlmodel.ChPodK8sEnv | mysqlmodel.ChPodK8sEnvs | mysqlmodel.ChPodK8sLabel |
		mysqlmodel.ChPodK8sLabels

	GetID() int
	GetUpdatedAt() time.Time
}

// ch资源的组合key
type ChModelKey interface {
	PrometheusTargetLabelKey | PrometheusAPPLabelKey | IntEnumTagKey | StringEnumTagKey | VtapPortKey | IPResourceKey |
		PortIDKey | PortIPKey | PortDeviceKey | IPRelationKey | TapTypeKey | NodeTypeKey | PolicyKey |
		IDKey | DeviceKey | IDKeyKey
}

type SubscriberChModelKey interface {
	IDKey | DeviceKey | IDKeyKey

	Map() map[string]interface{}
}
