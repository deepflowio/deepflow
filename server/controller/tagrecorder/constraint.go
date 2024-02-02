/*
 * Copyright (c) 2023 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

// 资源的MySQL orm对象
type MySQLChModel interface {
	mysql.ChPrometheusTargetLabelLayout | mysql.ChTargetLabel | mysql.ChAPPLabel | mysql.ChPrometheusMetricName | mysql.ChPrometheusLabelName |
		mysql.ChPrometheusMetricAPPLabelLayout | mysql.ChPodServiceK8sLabels | mysql.ChPodServiceK8sLabel | mysql.ChOSAppTags |
		mysql.ChOSAppTag | mysql.ChPodNSCloudTags | mysql.ChChostCloudTags | mysql.ChPodNSCloudTag | mysql.ChChostCloudTag | mysql.ChIntEnum |
		mysql.ChStringEnum | mysql.ChPodIngress | mysql.ChPodGroupPort | mysql.ChPodPort | mysql.ChVTapPort | mysql.ChAZ | mysql.ChIPResource | mysql.ChPodK8sLabel |
		mysql.ChLBListener | mysql.ChPodNodePort | mysql.ChIPPort | mysql.ChDevicePort | mysql.ChRegion | mysql.ChVPC |
		mysql.ChDevice | mysql.ChIPRelation | mysql.ChPodGroup | mysql.ChNetwork | mysql.ChPod | mysql.ChPodCluster |
		mysql.ChPodNode | mysql.ChPodNamespace | mysql.ChTapType | mysql.ChVTap | mysql.ChPodK8sLabels | mysql.ChNodeType | mysql.ChGProcess | mysql.ChPodK8sAnnotation | mysql.ChPodK8sAnnotations |
		mysql.ChPodServiceK8sAnnotation | mysql.ChPodServiceK8sAnnotations |
		mysql.ChPodK8sEnv | mysql.ChPodK8sEnvs | mysql.ChPolicy | mysql.ChNpbTunnel
}

// ch资源的组合key
type ChModelKey interface {
	PrometheusTargetLabelKey | PrometheusAPPLabelKey | OSAPPTagKey | OSAPPTagsKey | CloudTagsKey | CloudTagKey | IntEnumTagKey | StringEnumTagKey | VtapPortKey | IPResourceKey | K8sLabelKey | PortIDKey | PortIPKey | PortDeviceKey | IDKey | DeviceKey |
		IPRelationKey | TapTypeKey | K8sLabelsKey | NodeTypeKey | K8sAnnotationKey | K8sAnnotationsKey |
		K8sEnvKey | K8sEnvsKey | PolicyKey
}
