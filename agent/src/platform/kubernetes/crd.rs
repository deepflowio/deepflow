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
use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube_derive::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::resource_watcher::Trimmable;

pub mod pingan {
    use super::*;

    use k8s_openapi::api::core::v1::ServicePort;

    #[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
    #[kube(
        group = "crd.pingan.org",
        version = "v1alpha1",
        kind = "ServiceRule",
        namespaced
    )]
    #[serde(rename_all = "camelCase")]
    pub struct ServiceRuleSpec {
        #[serde(rename = "clusterIP")]
        pub cluster_ip: Option<String>,
        pub ports: Option<Vec<ServicePort>>,
        pub selector: Option<BTreeMap<String, String>>,
        pub type_: Option<String>,
    }

    impl Trimmable for ServiceRule {
        fn trim(mut self) -> Self {
            let name = if let Some(name) = self.metadata.name.as_ref() {
                name
            } else {
                ""
            };
            let mut sr = Self::new(name, self.spec);
            sr.metadata = ObjectMeta {
                uid: self.metadata.uid.take(),
                name: self.metadata.name.take(),
                namespace: self.metadata.namespace.take(),
                annotations: self.metadata.annotations.take(),
                labels: self.metadata.labels.take(),
                ..Default::default()
            };
            sr
        }
    }
}

pub mod kruise {
    use super::*;

    use k8s_openapi::{
        api::core::v1::PodTemplateSpec, apimachinery::pkg::apis::meta::v1::LabelSelector,
    };

    #[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
    #[kube(
        group = "apps.kruise.io",
        version = "v1alpha1",
        kind = "CloneSet",
        namespaced
    )]
    #[serde(rename_all = "camelCase")]
    pub struct CloneSetSpec {
        pub relicas: Option<i32>,
        pub selector: LabelSelector,
        pub template: PodTemplateSpec,
    }

    impl Trimmable for CloneSet {
        fn trim(mut self) -> Self {
            let name = if let Some(name) = self.metadata.name.as_ref() {
                name
            } else {
                ""
            };
            let mut cs = Self::new(name, self.spec);
            cs.metadata = ObjectMeta {
                uid: self.metadata.uid.take(),
                name: self.metadata.name.take(),
                namespace: self.metadata.namespace.take(),
                labels: self.metadata.labels.take(),
                ..Default::default()
            };
            cs
        }
    }

    #[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
    #[kube(
        group = "apps.kruise.io",
        version = "v1beta1",
        kind = "StatefulSet",
        namespaced
    )]
    #[serde(rename_all = "camelCase")]
    pub struct StatefulSetSpec {
        pub relicas: Option<i32>,
        pub selector: LabelSelector,
        pub template: PodTemplateSpec,
    }

    impl Trimmable for StatefulSet {
        fn trim(mut self) -> Self {
            let name = if let Some(name) = self.metadata.name.as_ref() {
                name
            } else {
                ""
            };
            let mut ss = Self::new(name, self.spec);
            ss.metadata = ObjectMeta {
                uid: self.metadata.uid.take(),
                name: self.metadata.name.take(),
                namespace: self.metadata.namespace.take(),
                labels: self.metadata.labels.take(),
                ..Default::default()
            };
            ss
        }
    }
}

pub mod calico {
    use super::*;

    #[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
    #[kube(
        group = "crd.projectcalico.org",
        version = "v1",
        kind = "IpPool",
        namespaced
    )]
    #[serde(rename_all = "camelCase")]
    pub struct IpPoolSpec {
        pub cidr: Option<String>,
        pub disabled: Option<bool>,
    }

    impl Trimmable for IpPool {
        fn trim(mut self) -> Self {
            let name = if let Some(name) = self.metadata.name.as_ref() {
                name
            } else {
                ""
            };
            let mut res = Self::new(name, self.spec);
            res.metadata = ObjectMeta {
                uid: self.metadata.uid.take(),
                name: self.metadata.name.take(),
                ..Default::default()
            };
            res
        }
    }
}
