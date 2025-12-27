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

package kubernetes_gather

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/smartystreets/goconvey/convey"

	cloudconfig "github.com/deepflowio/deepflow/server/controller/cloud/config"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/genesis"
	gcommon "github.com/deepflowio/deepflow/server/controller/genesis/common"
)

func TestKubernetes(t *testing.T) {
	Convey("TestKubernetes", t, func() {
		k8sConfig := metadbmodel.SubDomain{
			Name:        "test_k8s",
			DisplayName: "test_k8s",
			ClusterID:   "d-01LMvvfQPZ",
			Config:      fmt.Sprintf(`{"node_port_name_regex": "","pod_net_ipv4_cidr_max_mask": %v,"pod_net_ipv6_cidr_max_mask": %v,"region_uuid": "%s","vpc_uuid": ""}`, common.K8S_POD_IPV4_NETMASK, common.K8S_POD_IPV6_NETMASK, common.DEFAULT_REGION),
		}

		k8s := NewKubernetesGather(metadb.DefaultDB, nil, &k8sConfig, cloudconfig.CloudConfig{}, false)
		type KResource struct {
			Pod        [][]byte `json:"*v1.Pod"`
			Info       [][]byte `json:"*version.Info"`
			Node       [][]byte `json:"*v1.Node"`
			Ingress    [][]byte `json:"*v1beta1.Ingress"`
			Service    [][]byte `json:"*v1.Service"`
			ConfigMap  [][]byte `json:"*v1.ConfigMap"`
			DaemonSet  [][]byte `json:"*v1.DaemonSet"`
			Namespace  [][]byte `json:"*v1.Namespace"`
			Deployment [][]byte `json:"*v1.Deployment"`
			ReplicaSet [][]byte `json:"*v1.ReplicaSet"`
		}

		type KDataResp struct {
			ClusterID string    `json:"cluster_id"`
			ErrorMSG  string    `json:"error_msg"`
			SyncedAt  string    `json:"synced_at"`
			Resources KResource `json:"resources"`
		}

		kJsonData, _ := os.ReadFile("./testfiles/kubernetes-info.json")
		var kData KDataResp
		json.Unmarshal(kJsonData, &kData)
		k8sEntries := map[string][][]byte{}
		k8sEntries["*v1.Pod"] = kData.Resources.Pod
		k8sEntries["*v1.Node"] = kData.Resources.Node
		k8sEntries["*version.Info"] = kData.Resources.Info
		k8sEntries["*v1beta1.Ingress"] = kData.Resources.Ingress
		k8sEntries["*v1.Service"] = kData.Resources.Service
		k8sEntries["*v1.ConfigMap"] = kData.Resources.ConfigMap
		k8sEntries["*v1.DaemonSet"] = kData.Resources.DaemonSet
		k8sEntries["*v1.Namespace"] = kData.Resources.Namespace
		k8sEntries["*v1.Deployment"] = kData.Resources.Deployment
		k8sEntries["*v1.ReplicaSet"] = kData.Resources.ReplicaSet
		k8sEntriesPatch := gomonkey.ApplyPrivateMethod(reflect.TypeOf(k8s), "getKubernetesEntries", func(_ *KubernetesGather) (map[string][][]byte, error) {
			return k8sEntries, nil
		})
		defer k8sEntriesPatch.Reset()

		g := genesis.NewGenesis(context.Background(), true, &config.ControllerConfig{})
		vJsonData, _ := os.ReadFile("./testfiles/vinterfaces.json")
		var vData gcommon.GenesisSyncDataResponse
		json.Unmarshal(vJsonData, &vData)
		vinterfacesInfoPatch := gomonkey.ApplyMethod(reflect.TypeOf(g), "GetGenesisSyncResponse", func(_ *genesis.Genesis, _ int) (gcommon.GenesisSyncDataResponse, error) {
			return vData, nil
		})
		defer vinterfacesInfoPatch.Reset()

		k8sGatherData, _ := k8s.GetKubernetesGatherData()
		Convey("k8sGatherResource number should be equal", func() {
			So(len(k8sGatherData.PodNodes), ShouldEqual, 2)
			So(len(k8sGatherData.PodNamespaces), ShouldEqual, 7)
			So(len(k8sGatherData.PodGroups), ShouldEqual, 11)
			So(len(k8sGatherData.PodReplicaSets), ShouldEqual, 4)
			So(len(k8sGatherData.PodServices), ShouldEqual, 4)
			So(len(k8sGatherData.PodServicePorts), ShouldEqual, 6)
			So(len(k8sGatherData.PodGroupPorts), ShouldEqual, 6)
			So(len(k8sGatherData.PodIngresses), ShouldEqual, 1)
			So(len(k8sGatherData.PodIngressRules), ShouldEqual, 2)
			So(len(k8sGatherData.PodIngressRuleBackends), ShouldEqual, 2)
			So(len(k8sGatherData.Pods), ShouldEqual, 15)
			So(len(k8sGatherData.PodServiceSubnets), ShouldEqual, 1)
			So(len(k8sGatherData.PodNodeSubnets), ShouldEqual, 1)
			So(len(k8sGatherData.PodSubnets), ShouldEqual, 1)
			So(len(k8sGatherData.PodServiceVInterfaces), ShouldEqual, 4)
			So(len(k8sGatherData.PodNodeVInterfaces), ShouldEqual, 2)
			So(len(k8sGatherData.PodVInterfaces), ShouldEqual, 9)
			So(len(k8sGatherData.PodServiceIPs), ShouldEqual, 4)
			So(len(k8sGatherData.PodNodeIPs), ShouldEqual, 2)
			So(len(k8sGatherData.PodIPs), ShouldEqual, 9)
		})
	})
}
