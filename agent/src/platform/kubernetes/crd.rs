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
use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube_derive::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::resource_watcher::Trimmable;

pub mod pingan_cloud {
    use super::*;

    use k8s_openapi::api::core::v1::{ServicePort, ServiceStatus};

    #[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
    #[kube(
        group = "crd.pingan.org",
        version = "v1alpha1",
        kind = "ServiceRule",
        namespaced,
        status = "ServiceStatus"
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
            if let Some(svc_status) = self.status.take() {
                sr.status = Some(ServiceStatus {
                    load_balancer: svc_status.load_balancer,
                    ..Default::default()
                });
            }
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
        pub replicas: Option<i32>,
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
        pub replicas: Option<i32>,
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

pub mod opengauss {
    use super::*;

    #[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
    #[kube(
        group = "opengauss.cmbc.com.cn",
        version = "v1",
        kind = "OpenGaussCluster",
        namespaced
    )]
    #[serde(rename_all = "camelCase")]
    pub struct OpenGaussClusterSpec {}

    impl Trimmable for OpenGaussCluster {
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

pub mod tkex {
    use super::*;

    use k8s_openapi::{
        api::core::v1::PodTemplateSpec, apimachinery::pkg::apis::meta::v1::LabelSelector,
    };

    #[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
    #[kube(
        group = "platform.stke",
        version = "v1alpha1",
        kind = "StatefulSetPlus",
        namespaced
    )]
    #[serde(rename_all = "camelCase")]
    pub struct StatefulSetPlusSpec {
        pub replicas: Option<i32>,
        pub selector: LabelSelector,
        pub template: PodTemplateSpec,
    }

    impl Trimmable for StatefulSetPlus {
        fn trim(mut self) -> Self {
            let name = if let Some(name) = self.metadata.name.as_ref() {
                name
            } else {
                ""
            };
            let mut ssp = Self::new(name, self.spec);
            ssp.metadata = ObjectMeta {
                uid: self.metadata.uid.take(),
                name: self.metadata.name.take(),
                namespace: self.metadata.namespace.take(),
                labels: self.metadata.labels.take(),
                ..Default::default()
            };
            ssp
        }
    }
}

pub mod legacy {
    use super::*;

    use k8s_openapi::api::networking::v1::IngressTLS;

    #[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
    pub struct IngressBackend {
        pub resource: Option<k8s_openapi::api::core::v1::TypedLocalObjectReference>,
        pub service_name: Option<String>,
        pub service_port: Option<k8s_openapi::apimachinery::pkg::util::intstr::IntOrString>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
    pub struct IngressRule {
        pub host: Option<String>,
        pub http: Option<HTTPIngressRuleValue>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
    pub struct HTTPIngressRuleValue {
        pub paths: Option<Vec<HTTPIngressPath>>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
    pub struct HTTPIngressPath {
        pub backend: IngressBackend,
        pub path: Option<String>,
        pub path_type: Option<String>,
    }

    pub mod networking {
        use super::*;

        #[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
        #[kube(
            group = "networking.k8s.io",
            version = "v1beta1",
            kind = "Ingress",
            namespaced
        )]
        #[serde(rename_all = "camelCase")]
        pub struct IngressSpec {
            pub backend: Option<IngressBackend>,
            pub ingress_class_name: Option<String>,
            pub rules: Option<Vec<IngressRule>>,
            pub tls: Option<Vec<IngressTLS>>,
        }

        impl Trimmable for Ingress {
            fn trim(mut self) -> Self {
                let name = if let Some(name) = self.metadata.name.as_ref() {
                    name
                } else {
                    ""
                };
                let mut resource = Self::new(name, self.spec);
                resource.metadata = ObjectMeta {
                    uid: self.metadata.uid.take(),
                    name: self.metadata.name.take(),
                    namespace: self.metadata.namespace.take(),
                    ..Default::default()
                };
                resource
            }
        }
    }

    pub mod extensions {
        use super::*;

        #[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
        #[kube(
            group = "extensions",
            version = "v1beta1",
            kind = "Ingress",
            namespaced
        )]
        #[serde(rename_all = "camelCase")]
        pub struct IngressSpec {
            pub backend: Option<IngressBackend>,
            pub ingress_class_name: Option<String>,
            pub rules: Option<Vec<IngressRule>>,
            pub tls: Option<Vec<IngressTLS>>,
        }

        impl Trimmable for Ingress {
            fn trim(mut self) -> Self {
                let name = if let Some(name) = self.metadata.name.as_ref() {
                    name
                } else {
                    ""
                };
                let mut resource = Self::new(name, self.spec);
                resource.metadata = ObjectMeta {
                    uid: self.metadata.uid.take(),
                    name: self.metadata.name.take(),
                    namespace: self.metadata.namespace.take(),
                    ..Default::default()
                };
                resource
            }
        }
    }
}
