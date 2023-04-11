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
use std::collections::BTreeMap;

use k8s_openapi::{api::core::v1::ServicePort, apimachinery::pkg::apis::meta::v1::ObjectMeta};
use kube_derive::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::resource_watcher::Trimmable;

pub mod pingan {
    use super::*;

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
            let mut sr = ServiceRule::new(name, self.spec);
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
