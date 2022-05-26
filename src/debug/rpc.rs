use std::sync::Arc;

use log::warn;
use parking_lot::RwLock;
use prost::Message as ProstMessage;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use super::error::{Error, Result};
use super::{chunk_string_payload, Message, Module, MAX_MESSAGE_SIZE};

use crate::common::platform_data::PlatformData;
use crate::common::policy::{Acl, Cidr, IpGroupData, PeerConnection};
use crate::config::RuntimeConfig;
use crate::exception::ExceptionHandler;
use crate::proto::trident::{self, SyncResponse};
use crate::rpc::{Session, StaticConfig, Status, Synchronizer};

pub struct RpcDebugger {
    session: Arc<Session>,
    status: Arc<RwLock<Status>>,
    config: Arc<StaticConfig>,
    rt: Runtime,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ConfigResp {
    status: i32,
    version_platform_data: u64,
    version_acls: u64,
    version_groups: u64,
    revision: String,
    config: String,
    self_update_url: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum RpcMessage {
    Config(Option<String>),
    PlatformData(Option<Vec<String>>),
    TapTypes(Option<Vec<String>>),
    Cidr(Option<Vec<String>>),
    Groups(Option<Vec<String>>),
    Acls(Option<Vec<String>>),
    Segments(Option<Vec<String>>),
    Version(Option<String>),
    Err(String),
    Fin,
}

impl RpcDebugger {
    pub(super) fn new(
        session: Arc<Session>,
        config: Arc<StaticConfig>,
        status: Arc<RwLock<Status>>,
    ) -> Self {
        Self {
            session,
            status,
            config,
            rt: Runtime::new().unwrap(),
        }
    }

    async fn get_rpc_response(&self) -> Result<tonic::Response<SyncResponse>, tonic::Status> {
        let exception_handler = ExceptionHandler::default();
        let req =
            Synchronizer::generate_sync_request(&self.config, &self.status, 0, &exception_handler);
        self.session.update_current_server().await;

        let client = self
            .session
            .get_client()
            .ok_or(tonic::Status::not_found("rpc client not connected"))?;

        let mut client = trident::synchronizer_client::SynchronizerClient::new(client);
        let resp = client.sync(req).await?;
        Ok(resp)
    }

    pub(super) fn basic_config(&self) -> Result<Vec<Message<RpcMessage>>> {
        let mut resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();
        if resp.config.is_none() {
            return Err(Error::NotFound(String::from(
                " sync response's config not found",
            )));
        }
        let c = RuntimeConfig::try_from(resp.config.take().unwrap())?;
        let config = ConfigResp {
            status: resp.status() as i32,
            version_platform_data: resp.version_platform_data(),
            version_groups: resp.version_groups(),
            revision: resp.revision.take().unwrap_or_default(),
            config: format!("{:?}", c),
            version_acls: resp.version_acls(),
            self_update_url: resp.self_update_url.take().unwrap_or_default(),
        };

        let c = format!("{:?}", config);
        let mut res = vec![];
        if c.len() > MAX_MESSAGE_SIZE {
            // String::truncate 削到char的边界的时候会panic
            let mut c = c.into_bytes();
            c.truncate(MAX_MESSAGE_SIZE);
            match String::from_utf8(c) {
                Ok(s) => {
                    res.push(Message {
                        module: Module::Rpc,
                        msg: RpcMessage::Config(Some(s)),
                    });
                }
                Err(e) => {
                    warn!("parse rpc basic config: {}", e);
                }
            }
        }
        res.push(Message {
            module: Module::Rpc,
            msg: RpcMessage::Fin,
        });

        Ok(res)
    }

    pub(super) fn tap_types(&self) -> Result<Vec<Message<RpcMessage>>> {
        let resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        fn truncate_fn(res: &mut Vec<Message<RpcMessage>>, s: String) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::TapTypes(Some(vec![s])),
            });
        }

        fn push_fn(res: &mut Vec<Message<RpcMessage>>, cache: &mut Option<Vec<String>>) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::TapTypes(cache.take()),
            });
        }

        let mut res = chunk_string_payload(
            resp.tap_types.into_iter().map(|t| format!("{:?}", t)),
            truncate_fn,
            push_fn,
        );

        res.push(Message {
            module: Module::Rpc,
            msg: RpcMessage::Fin,
        });

        Ok(res)
    }

    pub(super) fn cidrs(&self) -> Result<Vec<Message<RpcMessage>>> {
        let resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        if resp.version_platform_data() == 0 {
            return Err(Error::NotFound(String::from("cidrs data in preparation")));
        }

        let platform_data = trident::PlatformData::decode_length_delimited(resp.platform_data())
            .map_err(|e| Error::ProstDecode(e))?;
        let cidrs = platform_data
            .cidrs
            .into_iter()
            .filter_map(|c| (&c).try_into().ok())
            .map(|c: Cidr| format!("{:?}", c));

        fn truncate_fn(res: &mut Vec<Message<RpcMessage>>, s: String) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::Cidr(Some(vec![s])),
            });
        }

        fn push_fn(res: &mut Vec<Message<RpcMessage>>, cache: &mut Option<Vec<String>>) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::Cidr(cache.take()),
            });
        }

        let mut res = chunk_string_payload(cidrs, truncate_fn, push_fn);

        res.push(Message {
            module: Module::Rpc,
            msg: RpcMessage::Fin,
        });

        Ok(res)
    }

    pub(super) fn platform_data(&self) -> Result<Vec<Message<RpcMessage>>> {
        let resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        if resp.version_platform_data() == 0 {
            return Err(Error::NotFound(String::from(
                "platform data in preparation",
            )));
        }

        let platform_data = trident::PlatformData::decode_length_delimited(resp.platform_data())
            .map_err(|e| Error::ProstDecode(e))?;

        let datas = platform_data
            .interfaces
            .into_iter()
            .filter_map(|p| (&p).try_into().ok())
            .map(|p: PlatformData| format!("{:?}", p));

        let peers = platform_data
            .peer_connections
            .into_iter()
            .map(|p| PeerConnection::from(&p))
            .map(|p: PeerConnection| format!("{:?}", p));

        let iter = datas.chain(peers);

        fn truncate_fn(res: &mut Vec<Message<RpcMessage>>, s: String) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::PlatformData(Some(vec![s])),
            });
        }

        fn push_fn(res: &mut Vec<Message<RpcMessage>>, cache: &mut Option<Vec<String>>) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::PlatformData(cache.take()),
            });
        }

        let mut res = chunk_string_payload(iter, truncate_fn, push_fn);

        res.push(Message {
            module: Module::Rpc,
            msg: RpcMessage::Fin,
        });

        Ok(res)
    }

    pub(super) fn ip_groups(&self) -> Result<Vec<Message<RpcMessage>>> {
        let resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        if resp.version_groups() == 0 {
            return Err(Error::NotFound(String::from(
                "ip groups data in preparation",
            )));
        }

        let groups = trident::Groups::decode_length_delimited(resp.groups())
            .map_err(|e| Error::ProstDecode(e))?;

        let groups = groups
            .groups
            .into_iter()
            .filter_map(|g| (&g).try_into().ok())
            .map(|i: IpGroupData| format!("{:?}", i));

        fn truncate_fn(res: &mut Vec<Message<RpcMessage>>, s: String) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::Groups(Some(vec![s])),
            });
        }

        fn push_fn(res: &mut Vec<Message<RpcMessage>>, cache: &mut Option<Vec<String>>) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::Groups(cache.take()),
            });
        }

        let mut res = chunk_string_payload(groups, truncate_fn, push_fn);

        res.push(Message {
            module: Module::Rpc,
            msg: RpcMessage::Fin,
        });

        Ok(res)
    }

    pub(super) fn flow_acls(&self) -> Result<Vec<Message<RpcMessage>>> {
        let resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        if resp.version_acls() == 0 {
            return Err(Error::NotFound(String::from(
                "flow acls data in preparation",
            )));
        }
        let pb_acls = trident::FlowAcls::decode_length_delimited(resp.flow_acls())
            .map_err(|e| Error::ProstDecode(e))?;

        let acls = pb_acls.flow_acl.into_iter().map(|a| {
            let acl = Acl::try_from(a);
            if acl.is_err() {
                return format!("{:?}", acl.unwrap_err());
            } else {
                return format!("{}", acl.unwrap());
            }
        });

        fn truncate_fn(res: &mut Vec<Message<RpcMessage>>, s: String) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::Acls(Some(vec![s])),
            });
        }

        fn push_fn(res: &mut Vec<Message<RpcMessage>>, cache: &mut Option<Vec<String>>) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::Acls(cache.take()),
            });
        }

        let mut res = chunk_string_payload(acls, truncate_fn, push_fn);

        res.push(Message {
            module: Module::Rpc,
            msg: RpcMessage::Fin,
        });

        Ok(res)
    }

    pub(super) fn local_segments(&self) -> Result<Vec<Message<RpcMessage>>> {
        let resp = self
            .rt
            .block_on(self.get_rpc_response())
            .map_err(|e| Error::Tonic(e))?
            .into_inner();

        fn truncate_fn(res: &mut Vec<Message<RpcMessage>>, s: String) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::Segments(Some(vec![s])),
            });
        }

        fn push_fn(res: &mut Vec<Message<RpcMessage>>, cache: &mut Option<Vec<String>>) {
            res.push(Message {
                module: Module::Rpc,
                msg: RpcMessage::Segments(cache.take()),
            });
        }

        let mut res = chunk_string_payload(
            resp.local_segments.into_iter().map(|s| format!("{:?}", s)),
            truncate_fn,
            push_fn,
        );

        res.push(Message {
            module: Module::Rpc,
            msg: RpcMessage::Fin,
        });

        Ok(res)
    }

    pub(super) fn current_version(&self) -> Result<Vec<Message<RpcMessage>>> {
        let status = self.status.read();
        let version = format!(
            "platformData version: {}\n groups version: {}\nflowAcls version: {}",
            status.version_platform_data, status.version_groups, status.version_acls
        );

        Ok(vec![
            Message {
                module: Module::Rpc,
                msg: RpcMessage::Version(Some(version)),
            },
            Message {
                module: Module::Rpc,
                msg: RpcMessage::Fin,
            },
        ])
    }
}
