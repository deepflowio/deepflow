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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

// 资源的MySQL orm对象
type MySQLChModel interface {
	metadbmodel.ChUser | metadbmodel.ChAlarmPolicy | metadbmodel.ChPrometheusTargetLabelLayout | metadbmodel.ChTargetLabel | metadbmodel.ChAPPLabel | metadbmodel.ChPrometheusMetricName | metadbmodel.ChPrometheusLabelName |
		metadbmodel.ChPrometheusMetricAPPLabelLayout | metadbmodel.ChPodServiceK8sLabels | metadbmodel.ChPodServiceK8sLabel | metadbmodel.ChOSAppTags |
		metadbmodel.ChOSAppTag | metadbmodel.ChPodNSCloudTags | metadbmodel.ChChostCloudTags | metadbmodel.ChPodNSCloudTag | metadbmodel.ChChostCloudTag | metadbmodel.ChIntEnum |
		metadbmodel.ChStringEnum | metadbmodel.ChPodIngress | metadbmodel.ChVTapPort | metadbmodel.ChAZ | metadbmodel.ChIPResource | metadbmodel.ChPodK8sLabel |
		metadbmodel.ChLBListener | metadbmodel.ChRegion | metadbmodel.ChVPC |
		metadbmodel.ChDevice | metadbmodel.ChIPRelation | metadbmodel.ChPodGroup | metadbmodel.ChNetwork | metadbmodel.ChPod | metadbmodel.ChPodCluster |
		metadbmodel.ChPodNode | metadbmodel.ChPodNamespace | metadbmodel.ChTapType | metadbmodel.ChVTap | metadbmodel.ChPodK8sLabels | metadbmodel.ChNodeType | metadbmodel.ChGProcess | metadbmodel.ChPodK8sAnnotation | metadbmodel.ChPodK8sAnnotations |
		metadbmodel.ChPodServiceK8sAnnotation | metadbmodel.ChPodServiceK8sAnnotations |
		metadbmodel.ChPodK8sEnv | metadbmodel.ChPodK8sEnvs | metadbmodel.ChPodService | metadbmodel.ChChost | metadbmodel.ChPolicy | metadbmodel.ChNpbTunnel
}

// ch资源的组合key
type ChModelKey interface {
	PrometheusTargetLabelKey | PrometheusAPPLabelKey | OSAPPTagKey | OSAPPTagsKey | CloudTagsKey | CloudTagKey | IntEnumTagKey | StringEnumTagKey | VtapPortKey | IPResourceKey | K8sLabelKey | PortIDKey | PortIPKey | PortDeviceKey | IDKey | DeviceKey |
		IPRelationKey | TapTypeKey | K8sLabelsKey | NodeTypeKey | K8sAnnotationKey | K8sAnnotationsKey |
		K8sEnvKey | K8sEnvsKey | PolicyKey
}
