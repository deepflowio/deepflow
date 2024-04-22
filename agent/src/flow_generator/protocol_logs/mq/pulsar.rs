#[path = "pulsar.proto.rs"]
mod pulsar_proto;

use prost::Message;
use pulsar_proto::{
    base_command::Type as CommandType, BaseCommand, BrokerEntryMetadata, MessageMetadata,
};
use serde::Serialize;
use std::collections::HashMap;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    flow_generator::{
        error::Result,
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response, TraceInfo},
            AppProtoHead, L7ResponseStatus, LogMessageType,
        },
    },
    utils::bytes::read_u32_be,
};

// ProtocolVersion in PulsarApi.proto
const MAX_PROTOCOL_VERSION: i32 = 21;

struct TopicMap<K, V, const N: usize>
where
    K: Eq + std::hash::Hash,
{
    kv: HashMap<K, V>,
    list: Vec<(K, V)>,
    use_map: bool,
}

impl<K, V, const N: usize> TopicMap<K, V, N>
where
    K: Eq + std::hash::Hash,
{
    fn insert(&mut self, id: K, topic: V) {
        if self.use_map {
            self.kv.insert(id, topic);
        } else {
            for (k, v) in self.list.iter_mut() {
                if *k == id {
                    *v = topic;
                    return;
                }
            }
            if self.list.len() == N {
                self.use_map = true;
                self.kv = self.list.drain(..).collect();
                self.kv.insert(id, topic);
            } else {
                self.list.push((id, topic));
            }
        }
    }

    fn get(&self, id: &K) -> Option<&V> {
        if self.use_map {
            self.kv.get(id)
        } else {
            self.list.iter().find(|(k, _)| k == id).map(|(_, v)| v)
        }
    }

    fn new() -> Self {
        Self {
            kv: HashMap::new(),
            list: Vec::new(),
            use_map: false,
        }
    }
}

type PulsarTopicMap = TopicMap<u64, String, 16>;

#[derive(Serialize, Debug, Default, Clone)]
pub struct PulsarInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    rtt: u64,

    command: Box<BaseCommand>,
    broker_entry_metadata: Option<BrokerEntryMetadata>,
    message_metadata: Box<Option<MessageMetadata>>,

    // min(CommandConnect.protocol_version, CommandConnected.protocol_version)
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<i32>,
    // persistent://public/default/my-topic
    //              tenant namespace topic
    #[serde(skip_serializing_if = "Option::is_none")]
    topic: Option<String>,
    // CommandConnect.proxy_to_broker_url
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    // MessageMetadata.sequence_id
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<u32>,
    // ledgerId:entryId:partitionIndex:batchIndex
    #[serde(skip_serializing_if = "Option::is_none")]
    x_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    span_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    req_len: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_len: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_status: Option<L7ResponseStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resp_exception: Option<String>,
}

pub struct PulsarLog {
    perf_stats: Option<L7PerfStats>,

    version: i32,
    domain: Option<String>,

    producer_topic: PulsarTopicMap,
    consumer_topic: PulsarTopicMap,
}

impl Default for PulsarLog {
    fn default() -> Self {
        Self {
            perf_stats: None,
            version: MAX_PROTOCOL_VERSION,
            domain: None,
            producer_topic: PulsarTopicMap::new(),
            consumer_topic: PulsarTopicMap::new(),
        }
    }
}

macro_rules! check_exists {
    ($command:expr, $field:ident) => {
        if $command.$field.is_none() {
            return None;
        }
    };
}

macro_rules! check {
    ($command:expr, $code:expr, $exception:expr) => {
        if let Some(x) = &$command {
            $code = x.error;
            $exception = x.message.clone();
        }
    };
}

macro_rules! get_req {
    ($command:expr, $x:ident) => {{
        let obj = $command.$x.as_ref()?;
        Some(obj.request_id as u64)
    }};
}

macro_rules! get_msg_req {
    ($command:expr, $x:ident) => {{
        let obj = $command.$x.as_ref()?;
        let producer_id = obj.producer_id as u16 as u64;
        let sequence_id = obj.sequence_id as u16 as u64;
        Some((producer_id << 16) | sequence_id)
    }};
}

macro_rules! update_topic {
    ($self:expr, $topic_map:expr, $id:ident, $x:ident) => {{
        let id = $self.command.$x.as_ref()?.$id;
        $self.topic = $topic_map.get(&id).cloned();
    }};
}

impl PulsarInfo {
    fn get_request_id(&self) -> Option<u64> {
        let command = self.command.as_ref();
        match command.r#type() {
            CommandType::Ack => None,
            CommandType::Flow => None,
            CommandType::Message => None,
            CommandType::RedeliverUnacknowledgedMessages => None,
            CommandType::ReachedEndOfTopic => None,
            CommandType::ActiveConsumerChange => None,
            CommandType::AckResponse => None,
            CommandType::WatchTopicList => None,
            CommandType::WatchTopicListSuccess => None,
            CommandType::WatchTopicUpdate => None,
            CommandType::WatchTopicListClose => None,
            CommandType::TopicMigrated => None,

            CommandType::Connect => None,
            CommandType::Connected => None,

            CommandType::Producer => get_req!(command, producer),
            CommandType::ProducerSuccess => get_req!(command, producer_success),

            CommandType::Send => get_msg_req!(command, send),
            CommandType::SendReceipt => get_msg_req!(command, send_receipt),
            CommandType::SendError => get_msg_req!(command, send_error),

            CommandType::Ping => None,
            CommandType::Pong => None,

            CommandType::Lookup => get_req!(command, lookup_topic),
            CommandType::LookupResponse => get_req!(command, lookup_topic_response),

            CommandType::PartitionedMetadata => get_req!(command, partition_metadata),
            CommandType::PartitionedMetadataResponse => {
                get_req!(command, partition_metadata_response)
            }

            CommandType::GetSchema => get_req!(command, get_schema),
            CommandType::GetSchemaResponse => get_req!(command, get_schema_response),

            CommandType::ConsumerStats => get_req!(command, consumer_stats),
            CommandType::ConsumerStatsResponse => get_req!(command, consumer_stats_response),

            CommandType::GetLastMessageId => get_req!(command, get_last_message_id),
            CommandType::GetLastMessageIdResponse => {
                get_req!(command, get_last_message_id_response)
            }

            CommandType::GetTopicsOfNamespace => get_req!(command, get_topics_of_namespace),
            CommandType::GetTopicsOfNamespaceResponse => {
                get_req!(command, get_topics_of_namespace_response)
            }

            CommandType::AuthChallenge => None,
            CommandType::AuthResponse => None,

            CommandType::GetOrCreateSchema => get_req!(command, get_or_create_schema),
            CommandType::GetOrCreateSchemaResponse => {
                get_req!(command, get_or_create_schema_response)
            }

            CommandType::NewTxn => get_req!(command, new_txn),
            CommandType::NewTxnResponse => get_req!(command, new_txn_response),

            CommandType::AddPartitionToTxn => get_req!(command, add_partition_to_txn),
            CommandType::AddPartitionToTxnResponse => {
                get_req!(command, add_partition_to_txn_response)
            }

            CommandType::AddSubscriptionToTxn => get_req!(command, add_subscription_to_txn),
            CommandType::AddSubscriptionToTxnResponse => {
                get_req!(command, add_partition_to_txn_response)
            }

            CommandType::EndTxn => get_req!(command, end_txn),
            CommandType::EndTxnResponse => get_req!(command, end_txn_response),

            CommandType::EndTxnOnPartition => get_req!(command, end_txn_on_partition),
            CommandType::EndTxnOnPartitionResponse => {
                get_req!(command, end_txn_on_partition_response)
            }

            CommandType::EndTxnOnSubscription => get_req!(command, end_txn_on_subscription),
            CommandType::EndTxnOnSubscriptionResponse => {
                get_req!(command, end_txn_on_subscription_response)
            }

            CommandType::TcClientConnectRequest => get_req!(command, tc_client_connect_request),
            CommandType::TcClientConnectResponse => get_req!(command, tc_client_connect_response),

            CommandType::Subscribe => get_req!(command, subscribe),
            CommandType::Unsubscribe => get_req!(command, unsubscribe),
            CommandType::CloseProducer => get_req!(command, close_producer),
            CommandType::CloseConsumer => get_req!(command, close_consumer),
            CommandType::Seek => get_req!(command, seek),
            CommandType::Error => get_req!(command, error),
            CommandType::Success => get_req!(command, success),
        }
    }

    fn parse_trace_span(&self, param: &ParseParam) -> (Option<String>, Option<String>) {
        let Some(config) = param.parse_config.map(|x| &x.l7_log_dynamic) else {
            return (None, None);
        };
        let Some(metadata) = self.message_metadata.as_ref() else {
            return (None, None);
        };

        let mut trace_id = None;
        let mut span_id = None;
        for kv in metadata.properties.iter() {
            let k = kv.key.as_str();
            let v = kv.value.as_str();
            for tt in config.trace_types.iter() {
                if tt.check(k) {
                    trace_id = tt.decode_trace_id(v).map(|x| x.to_string());
                    break;
                }
            }
            for st in config.span_types.iter() {
                if st.check(k) {
                    span_id = st.decode_span_id(v).map(|x| x.to_string());
                    break;
                }
            }
        }

        (trace_id, span_id)
    }

    fn parse_sequence_id(&self) -> Option<u32> {
        let metadata = self.message_metadata.as_ref().as_ref()?;
        Some(metadata.sequence_id as u32)
    }

    fn parse_x_request_id(&self) -> Option<String> {
        let message_id = if let Some(send) = &self.command.send {
            send.message_id.as_ref()?
        } else if let Some(message) = &self.command.message {
            &message.message_id
        } else {
            return None;
        };
        let partition = message_id.partition.unwrap_or(-1);
        let batch_index = message_id.batch_index.unwrap_or(-1);
        Some(format!(
            "{}:{}:{}:{}",
            message_id.ledger_id, message_id.entry_id, partition, batch_index
        ))
    }

    fn parse_domain(&self) -> Option<String> {
        let connect = self.command.connect.as_ref()?;
        connect.proxy_to_broker_url.as_ref().map(|x| x.to_string())
    }

    fn parse_version(&self) -> Option<i32> {
        if let Some(connect) = &self.command.connect {
            connect.protocol_version
        } else if let Some(connected) = &self.command.connected {
            connected.protocol_version
        } else {
            None
        }
    }

    fn get_topic(&self) -> Option<String> {
        let topic = if let Some(producer) = &self.command.producer {
            producer.topic.clone()
        } else if let Some(subscribe) = &self.command.subscribe {
            subscribe.topic.clone()
        } else {
            return None;
        };
        topic.split('/').last().map(|x| x.to_string())
    }

    fn update_topic(
        &mut self,
        producer_topic: &mut PulsarTopicMap,
        consumer_topic: &mut PulsarTopicMap,
    ) -> Option<()> {
        let command = self.command.as_ref();
        match command.r#type() {
            CommandType::Subscribe => {
                let consumer_id = command.subscribe.as_ref()?.consumer_id;
                let topic = self.get_topic()?;
                consumer_topic.insert(consumer_id, topic.clone());
                self.topic = Some(topic);
            }
            CommandType::Producer => {
                let producer_id = command.producer.as_ref()?.producer_id;
                let topic = self.get_topic()?;
                producer_topic.insert(producer_id, topic.clone());
                self.topic = Some(topic);
            }

            CommandType::Send => update_topic!(self, producer_topic, producer_id, send),
            CommandType::SendReceipt => {
                update_topic!(self, producer_topic, producer_id, send_receipt)
            }
            CommandType::SendError => update_topic!(self, producer_topic, producer_id, send_error),
            CommandType::CloseProducer => {
                update_topic!(self, producer_topic, producer_id, close_producer)
            }

            CommandType::Message => update_topic!(self, consumer_topic, consumer_id, message),
            CommandType::Ack => update_topic!(self, consumer_topic, consumer_id, ack),
            CommandType::AckResponse => {
                update_topic!(self, consumer_topic, consumer_id, ack_response)
            }
            CommandType::ActiveConsumerChange => {
                update_topic!(self, consumer_topic, consumer_id, active_consumer_change)
            }
            CommandType::Flow => update_topic!(self, consumer_topic, consumer_id, flow),
            CommandType::Unsubscribe => {
                update_topic!(self, consumer_topic, consumer_id, unsubscribe)
            }
            CommandType::Seek => update_topic!(self, consumer_topic, consumer_id, seek),
            CommandType::ReachedEndOfTopic => {
                update_topic!(self, consumer_topic, consumer_id, reached_end_of_topic)
            }
            CommandType::CloseConsumer => {
                update_topic!(self, consumer_topic, consumer_id, close_consumer)
            }
            CommandType::RedeliverUnacknowledgedMessages => update_topic!(
                self,
                consumer_topic,
                consumer_id,
                redeliver_unacknowledged_messages
            ),
            CommandType::ConsumerStats => {
                update_topic!(self, consumer_topic, consumer_id, consumer_stats)
            }

            _ => {}
        }
        Some(())
    }

    fn get_message_type(&self) -> LogMessageType {
        match self.command.r#type() {
            CommandType::Connect => LogMessageType::Request,
            CommandType::Connected => LogMessageType::Response,

            CommandType::Producer => LogMessageType::Request,
            CommandType::ProducerSuccess => LogMessageType::Response,

            CommandType::Send => LogMessageType::Request,
            CommandType::SendReceipt => LogMessageType::Response,
            CommandType::SendError => LogMessageType::Response,

            CommandType::Ping => LogMessageType::Request,
            CommandType::Pong => LogMessageType::Response,

            CommandType::Lookup => LogMessageType::Request,
            CommandType::LookupResponse => LogMessageType::Response,

            CommandType::PartitionedMetadata => LogMessageType::Request,
            CommandType::PartitionedMetadataResponse => LogMessageType::Response,

            CommandType::GetSchema => LogMessageType::Request,
            CommandType::GetSchemaResponse => LogMessageType::Response,

            CommandType::ConsumerStats => LogMessageType::Request,
            CommandType::ConsumerStatsResponse => LogMessageType::Response,

            CommandType::GetLastMessageId => LogMessageType::Request,
            CommandType::GetLastMessageIdResponse => LogMessageType::Response,

            CommandType::GetTopicsOfNamespace => LogMessageType::Request,
            CommandType::GetTopicsOfNamespaceResponse => LogMessageType::Response,

            CommandType::AuthChallenge => LogMessageType::Request,
            CommandType::AuthResponse => LogMessageType::Response,

            CommandType::GetOrCreateSchema => LogMessageType::Request,
            CommandType::GetOrCreateSchemaResponse => LogMessageType::Response,

            CommandType::NewTxn => LogMessageType::Request,
            CommandType::NewTxnResponse => LogMessageType::Response,

            CommandType::AddPartitionToTxn => LogMessageType::Request,
            CommandType::AddPartitionToTxnResponse => LogMessageType::Response,

            CommandType::AddSubscriptionToTxn => LogMessageType::Request,
            CommandType::AddSubscriptionToTxnResponse => LogMessageType::Response,

            CommandType::EndTxn => LogMessageType::Request,
            CommandType::EndTxnResponse => LogMessageType::Response,

            CommandType::EndTxnOnPartition => LogMessageType::Request,
            CommandType::EndTxnOnPartitionResponse => LogMessageType::Response,

            CommandType::EndTxnOnSubscription => LogMessageType::Request,
            CommandType::EndTxnOnSubscriptionResponse => LogMessageType::Response,

            CommandType::TcClientConnectRequest => LogMessageType::Request,
            CommandType::TcClientConnectResponse => LogMessageType::Response,

            CommandType::Subscribe => LogMessageType::Request,
            // Success or Error
            CommandType::Unsubscribe => LogMessageType::Request,
            // Success, Error
            CommandType::CloseProducer => LogMessageType::Request,
            // Success, Error
            CommandType::CloseConsumer => LogMessageType::Request,
            // Success, Error
            CommandType::Seek => LogMessageType::Request,
            // Success, Error
            CommandType::Error => LogMessageType::Response,
            CommandType::Success => LogMessageType::Response,

            CommandType::Ack => LogMessageType::Session,
            CommandType::Flow => LogMessageType::Session,
            CommandType::Message => LogMessageType::Session,
            CommandType::RedeliverUnacknowledgedMessages => LogMessageType::Session,
            CommandType::ReachedEndOfTopic => LogMessageType::Session,
            CommandType::ActiveConsumerChange => LogMessageType::Session,
            CommandType::AckResponse => LogMessageType::Session,
            CommandType::WatchTopicList => LogMessageType::Session,
            CommandType::WatchTopicListSuccess => LogMessageType::Session,
            CommandType::WatchTopicUpdate => LogMessageType::Session,
            CommandType::WatchTopicListClose => LogMessageType::Session,
            CommandType::TopicMigrated => LogMessageType::Session,
        }
    }

    fn update_response_info(&mut self) {
        let mut is_success = false;
        let mut code = None;
        let mut msg = None;
        match self.command.r#type() {
            CommandType::Connected
            | CommandType::ProducerSuccess
            | CommandType::SendReceipt
            | CommandType::Pong
            | CommandType::Success
            | CommandType::GetLastMessageIdResponse
            | CommandType::GetTopicsOfNamespaceResponse
            | CommandType::AuthResponse => {
                is_success = true;
            }
            _ => {}
        }
        if let Some(x) = &self.command.send_error {
            code = Some(x.error);
            msg = Some(x.message.clone());
        }
        if let Some(x) = &self.command.error {
            code = Some(x.error);
            msg = Some(x.message.clone());
        }
        if let Some(x) = &self.command.get_schema_response {
            code = x.error_code;
            msg = x.error_message.clone();
        }
        if let Some(x) = &self.command.consumer_stats_response {
            code = x.error_code;
            msg = x.error_message.clone();
        }
        if let Some(x) = &self.command.get_or_create_schema_response {
            code = x.error_code;
            msg = x.error_message.clone();
        }
        check!(self.command.lookup_topic_response, code, msg);
        check!(self.command.partition_metadata_response, code, msg);
        check!(self.command.new_txn_response, code, msg);
        check!(self.command.add_partition_to_txn_response, code, msg);
        check!(self.command.add_subscription_to_txn_response, code, msg);
        check!(self.command.end_txn_response, code, msg);
        check!(self.command.end_txn_on_partition_response, code, msg);
        check!(self.command.end_txn_on_subscription_response, code, msg);
        check!(self.command.tc_client_connect_response, code, msg);
        is_success |= code.is_none();
        if is_success {
            self.resp_status = Some(L7ResponseStatus::Ok);
            self.resp_code = None;
            self.resp_exception = None;
        } else {
            self.resp_status = Some(L7ResponseStatus::ServerError);
            self.resp_code = code;
            self.resp_exception = msg;
        }
    }

    fn parse<'a>(payload: &'a [u8], param: &ParseParam) -> Option<(&'a [u8], Self)> {
        let mut info = PulsarInfo::default();
        let total_size = read_u32_be(payload.get(0..4)?) as usize;
        let command_size = read_u32_be(payload.get(4..8)?) as usize;
        if total_size < 4 + command_size {
            return None;
        }
        let buf = payload.get(8..8 + command_size as usize)?;
        info.command = Box::new(BaseCommand::decode(buf).ok()?);
        let command = &info.command;
        match command.r#type() {
            CommandType::Ack => check_exists!(command, ack),
            CommandType::Flow => check_exists!(command, flow),
            CommandType::Message => check_exists!(command, message),
            CommandType::RedeliverUnacknowledgedMessages => {
                check_exists!(command, redeliver_unacknowledged_messages)
            }
            CommandType::ReachedEndOfTopic => check_exists!(command, reached_end_of_topic),
            CommandType::ActiveConsumerChange => check_exists!(command, active_consumer_change),
            CommandType::AckResponse => check_exists!(command, ack_response),
            CommandType::WatchTopicList => check_exists!(command, watch_topic_list),
            CommandType::WatchTopicListSuccess => check_exists!(command, watch_topic_list_success),
            CommandType::WatchTopicUpdate => check_exists!(command, watch_topic_update),
            CommandType::WatchTopicListClose => check_exists!(command, watch_topic_list_close),
            CommandType::TopicMigrated => check_exists!(command, topic_migrated),

            CommandType::Connect => check_exists!(command, connect),
            CommandType::Connected => check_exists!(command, connected),

            CommandType::Producer => check_exists!(command, producer),
            CommandType::ProducerSuccess => check_exists!(command, producer_success),

            CommandType::Send => check_exists!(command, send),
            CommandType::SendReceipt => check_exists!(command, send_receipt),
            CommandType::SendError => check_exists!(command, send_error),

            CommandType::Ping => check_exists!(command, ping),
            CommandType::Pong => check_exists!(command, pong),

            CommandType::Lookup => check_exists!(command, lookup_topic),
            CommandType::LookupResponse => check_exists!(command, lookup_topic_response),

            CommandType::PartitionedMetadata => check_exists!(command, partition_metadata),
            CommandType::PartitionedMetadataResponse => {
                check_exists!(command, partition_metadata_response)
            }

            CommandType::GetSchema => check_exists!(command, get_schema),
            CommandType::GetSchemaResponse => check_exists!(command, get_schema_response),

            CommandType::ConsumerStats => check_exists!(command, consumer_stats),
            CommandType::ConsumerStatsResponse => check_exists!(command, consumer_stats_response),

            CommandType::GetLastMessageId => check_exists!(command, get_last_message_id),
            CommandType::GetLastMessageIdResponse => {
                check_exists!(command, get_last_message_id_response)
            }

            CommandType::GetTopicsOfNamespace => check_exists!(command, get_topics_of_namespace),
            CommandType::GetTopicsOfNamespaceResponse => {
                check_exists!(command, get_topics_of_namespace_response)
            }

            CommandType::AuthChallenge => check_exists!(command, auth_challenge),
            CommandType::AuthResponse => check_exists!(command, auth_response),

            CommandType::GetOrCreateSchema => check_exists!(command, get_or_create_schema),
            CommandType::GetOrCreateSchemaResponse => {
                check_exists!(command, get_or_create_schema_response)
            }

            CommandType::NewTxn => check_exists!(command, new_txn),
            CommandType::NewTxnResponse => check_exists!(command, new_txn_response),

            CommandType::AddPartitionToTxn => check_exists!(command, add_partition_to_txn),
            CommandType::AddPartitionToTxnResponse => {
                check_exists!(command, add_partition_to_txn_response)
            }

            CommandType::AddSubscriptionToTxn => check_exists!(command, add_subscription_to_txn),
            CommandType::AddSubscriptionToTxnResponse => {
                check_exists!(command, add_partition_to_txn_response)
            }

            CommandType::EndTxn => check_exists!(command, end_txn),
            CommandType::EndTxnResponse => check_exists!(command, end_txn_response),

            CommandType::EndTxnOnPartition => check_exists!(command, end_txn_on_partition),
            CommandType::EndTxnOnPartitionResponse => {
                check_exists!(command, end_txn_on_partition_response)
            }

            CommandType::EndTxnOnSubscription => check_exists!(command, end_txn_on_subscription),
            CommandType::EndTxnOnSubscriptionResponse => {
                check_exists!(command, end_txn_on_subscription_response)
            }

            CommandType::TcClientConnectRequest => {
                check_exists!(command, tc_client_connect_request)
            }
            CommandType::TcClientConnectResponse => {
                check_exists!(command, tc_client_connect_response)
            }

            CommandType::Subscribe => check_exists!(command, subscribe),
            CommandType::Unsubscribe => check_exists!(command, unsubscribe),
            CommandType::CloseProducer => check_exists!(command, close_producer),
            CommandType::CloseConsumer => check_exists!(command, close_consumer),
            CommandType::Seek => check_exists!(command, seek),
            CommandType::Error => check_exists!(command, error),
            CommandType::Success => check_exists!(command, success),
        }
        let mut extra = payload.get(8 + command_size..4 + total_size)?;
        let payload = payload.get(4 + total_size..)?;
        if extra.len() > 0 {
            let mut magic = extra.get(0..2)?;
            if magic == b"\x0e\x02" {
                let size = read_u32_be(extra.get(2..6)?) as usize;
                let buf = extra.get(6..6 + size)?;
                info.broker_entry_metadata = Some(BrokerEntryMetadata::decode(buf).ok()?);
                extra = extra.get(6 + size..)?;
                magic = extra.get(0..2)?;
            }
            if magic != b"\x0e\x01" {
                return None;
            }
            let _checksum = read_u32_be(extra.get(2..6)?);
            let metadata_size = read_u32_be(extra.get(6..10)?) as usize;
            let buf = extra.get(10..10 + metadata_size)?;
            info.message_metadata = Box::new(Some(MessageMetadata::decode(buf).ok()?));
            let _payload = extra.get(10 + metadata_size..)?;
        }
        (info.trace_id, info.span_id) = info.parse_trace_span(param);
        info.x_request_id = info.parse_x_request_id();
        info.request_id = info.get_request_id().map(|x| x as u32);
        info.domain = info.parse_domain();
        info.version = info.parse_version();
        info.msg_type = info.get_message_type();
        match info.msg_type {
            LogMessageType::Response => {
                info.resp_len = Some(total_size as u32);
                info.update_response_info();
            }
            _ => info.req_len = Some(total_size as u32),
        }
        Some((payload, info))
    }
}

impl From<PulsarInfo> for L7ProtocolSendLog {
    fn from(info: PulsarInfo) -> Self {
        let flags = match info.is_tls {
            true => EbpfFlags::TLS.bits(),
            false => EbpfFlags::NONE.bits(),
        };

        let log = L7ProtocolSendLog {
            flags,
            version: info.version.map(|x| x.to_string()),
            req_len: info.req_len,
            resp_len: info.resp_len,
            req: L7Request {
                req_type: info.command.r#type().as_str_name().to_string(),
                domain: info.domain.unwrap_or_default(),
                resource: info.topic.clone().unwrap_or_default(),
                endpoint: info.topic.unwrap_or_default(),
                ..Default::default()
            },
            resp: L7Response {
                status: info.resp_status.unwrap_or_default(),
                code: info.resp_code,
                exception: info.resp_exception.unwrap_or_default(),
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: info.trace_id,
                span_id: info.span_id,
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                request_id: info.request_id,
                x_request_id_0: info.x_request_id,
                ..Default::default()
            }),
            ..Default::default()
        };
        log
    }
}

impl L7ProtocolInfoInterface for PulsarInfo {
    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn session_id(&self) -> Option<u32> {
        self.get_request_id().map(|x| x as u32)
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let (req, L7ProtocolInfo::PulsarInfo(rsp)) = (self, other) {
            req.resp_len = req.resp_len.or(rsp.resp_len);
            req.resp_status = req.resp_status.or(rsp.resp_status);
            req.resp_code = req.resp_code.or(rsp.resp_code);
            if req.resp_exception.is_none() {
                req.resp_exception = rsp.resp_exception.clone();
            }
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Pulsar,
            msg_type: self.msg_type,
            rrt: self.rtt,
        })
    }

    fn get_endpoint(&self) -> Option<String> {
        self.topic.clone()
    }

    fn get_request_domain(&self) -> String {
        self.domain.clone().unwrap_or_default()
    }
}

impl L7ProtocolParserInterface for PulsarLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }
        if payload.len() < 8 {
            return false;
        }
        PulsarInfo::parse(payload, param).is_some()
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let mut vec = Vec::new();
        let mut payload = payload;

        while let Some((tmp, mut info)) = PulsarInfo::parse(payload, param) {
            payload = tmp;
            self.version = self
                .version
                .min(info.version.unwrap_or(MAX_PROTOCOL_VERSION));
            self.domain = info.domain.clone().or(self.domain.clone());
            info.update_topic(&mut self.producer_topic, &mut self.consumer_topic);
            info.version = Some(self.version);
            info.domain = self.domain.clone();
            vec.push(L7ProtocolInfo::PulsarInfo(info));
        }

        for info in &mut vec {
            if let L7ProtocolInfo::PulsarInfo(info) = info {
                if info.msg_type != LogMessageType::Session {
                    info.cal_rrt(param, None).map(|rtt| {
                        info.rtt = rtt;
                        self.perf_stats.as_mut().map(|p| p.update_rrt(rtt));
                    });
                }

                info.is_tls = param.is_tls();

                match param.direction {
                    PacketDirection::ClientToServer => {
                        self.perf_stats.as_mut().map(|p| p.inc_req());
                    }
                    PacketDirection::ServerToClient => {
                        self.perf_stats.as_mut().map(|p| p.inc_resp());
                    }
                }
            }
        }

        if !param.parse_log {
            Ok(L7ParseResult::None)
        } else if vec.len() == 1 {
            Ok(L7ParseResult::Single(vec.remove(0)))
        } else if vec.len() > 1 {
            Ok(L7ParseResult::Multi(vec))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Pulsar
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use serde_json;
    use std::path::Path;
    use std::rc::Rc;
    use std::{cell::RefCell, fs};

    use super::*;

    use crate::{
        common::{flow::PacketDirection, l7_protocol_log::L7PerfCache, MetaPacket},
        config::{
            handler::{L7LogDynamicConfig, LogParserConfig, TraceType},
            ExtraLogFields,
        },
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/pulsar";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut pulsar = PulsarLog::default();
        for packet in packets.iter_mut() {
            packet.lookup_key.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };
            let param = &mut ParseParam::new(
                packet as &MetaPacket,
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );

            let config = L7LogDynamicConfig::new(
                "".to_owned(),
                vec![],
                vec![TraceType::Sw8, TraceType::TraceParent],
                vec![TraceType::Sw8, TraceType::TraceParent],
                ExtraLogFields::default(),
            );
            let parse_config = &LogParserConfig {
                l7_log_dynamic: config.clone(),
                ..Default::default()
            };

            param.set_log_parse_config(parse_config);

            if !pulsar.check_payload(payload, param) {
                output.push_str("not pulsar\n");
                continue;
            }

            let info = pulsar.parse_payload(payload, param);
            if let Ok(info) = info {
                match info {
                    L7ParseResult::Single(s) => {
                        output.push_str(&serde_json::to_string(&s).unwrap());
                        output.push_str("\n");
                    }
                    L7ParseResult::Multi(m) => {
                        for i in m {
                            output.push_str(&serde_json::to_string(&i).unwrap());
                            output.push_str("\n");
                        }
                    }
                    L7ParseResult::None => {
                        output.push_str("None\n");
                    }
                }
            } else {
                output.push_str(&format!("{:?}\n", PulsarInfo::default()));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("pulsar-producer.pcap", "pulsar-producer.result"),
            ("pulsar-consumer.pcap", "pulsar-consumer.result"),
        ];

        for item in files.iter() {
            let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
            let output = run(item.0);

            if output != expected {
                let output_path = Path::new("actual.txt");
                fs::write(&output_path, &output).unwrap();
                assert!(
                    output == expected,
                    "output different from expected {}, written to {:?}",
                    item.1,
                    output_path
                );
            }
        }
    }

    #[test]
    fn check_topicmap() {
        let mut map1: TopicMap<u64, u64, 16> = TopicMap::new();
        let mut map2: HashMap<u64, u64> = HashMap::new();
        for i in 0..5 {
            map1.insert(i, i);
            map2.insert(i, i);
        }
        for i in 0..32 {
            assert_eq!(map1.get(&i), map2.get(&i));
        }
        for i in 0..11 {
            map1.insert(i, i + 64);
            map2.insert(i, i + 64);
        }
        for i in 0..32 {
            assert_eq!(map1.get(&i), map2.get(&i));
        }
        for i in 0..32 {
            map1.insert(i, i + 128);
            map2.insert(i, i + 128);
        }
        for i in 0..32 {
            assert_eq!(map1.get(&i), map2.get(&i));
        }
    }
}
