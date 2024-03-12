use bitflags::bitflags;
use nom::{bytes, error, number, Err};
use serde::Serialize;
use std::fmt;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    config::handler::{L7LogDynamicConfig, TraceType},
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response, TraceInfo},
            value_is_default, value_is_negative, AppProtoHead, L7ResponseStatus, LogMessageType,
        },
    },
};

/// references:
///   1. the JMS repository: "https://github.com/apache/activemq-openwire"
///   2. ActiveMQ website: "https://activemq.apache.org"
///      !!! be careful that the mannuals are not always up-to-date
///   3. the CMS repository: "https://github.com/apache/activemq-cpp"
///      >>> recommend to read the source code of CMS, since it is more
///      >>> rust-likely implemented than the JMS repo

/*
1   WIREFORMAT_INFO
2   BROKER_INFO
3   CONNECTION_INFO
4   SESSION_INFO
5   CONSUMER_INFO
6   PRODUCER_INFO
7   TRANSACTION_INFO
8   DESTINATION_INFO
9   REMOVE_SUBSCRIPTION_INFO
10  KEEP_ALIVE_INFO
11  SHUTDOWN_INFO
12  REMOVE_INFO
14  CONTROL_COMMAND
15  FLUSH_COMMAND
16  CONNECTION_ERROR
17  CONSUMER_CONTROL
18  CONNECTION_CONTROL
19  PRODUCER_ACK
20  MESSAGE_PULL
21  MESSAGE_DISPATCH
22  MESSAGE_ACK
23  ACTIVEMQ_MESSAGE
24  ACTIVEMQ_BYTES_MESSAGE
25  ACTIVEMQ_MAP_MESSAGE
26  ACTIVEMQ_OBJECT_MESSAGE
27  ACTIVEMQ_STREAM_MESSAGE
28  ACTIVEMQ_TEXT_MESSAGE
29  ACTIVEMQ_BLOB_MESSAGE
30  RESPONSE
31  EXCEPTION_RESPONSE
32  DATA_RESPONSE
33  DATA_ARRAY_RESPONSE
34  INTEGER_RESPONSE
40  DISCOVERY_EVENT
50  JOURNAL_TOPIC_ACK (not in out-of-date OpenWire V2 Specification: "https://activemq.apache.org/openwire-version-2-specification")
52  JOURNAL_QUEUE_ACK (not in out-of-date OpenWire V2 Specification)
53  JOURNAL_TRACE
54  JOURNAL_TRANSACTION
55  DURABLE_SUBSCRIPTION_INFO
60  PARTIAL_COMMAND
61  PARTIAL_LAST_COMMAND
65  REPLAY
70  BYTE_TYPE
71  CHAR_TYPE
72  SHORT_TYPE
73  INTEGER_TYPE
74  LONG_TYPE
75  DOUBLE_TYPE
76  FLOAT_TYPE
77  STRING_TYPE
78  BOOLEAN_TYPE
79  BYTE_ARRAY_TYPE
90  MESSAGE_DISPATCH_NOTIFICATION
91  NETWORK_BRIDGE_FILTER
100 ACTIVEMQ_QUEUE
101 ACTIVEMQ_TOPIC
102 ACTIVEMQ_TEMP_QUEUE
103 ACTIVEMQ_TEMP_TOPIC
110 MESSAGE_ID
111 ACTIVEMQ_LOCAL_TRANSACTION_ID
112 ACTIVEMQ_XA_TRANSACTION_ID
120 CONNECTION_ID
121 SESSION_ID
122 CONSUMER_ID
123 PRODUCER_ID
124 BROKER_ID
 */

macro_rules! all_openwire_commands {
    ($($variant:ident($struct_name:ident, $command_id:expr)),* $(,)?) => {
        #[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
        pub enum OpenWireCommand {
            $($variant = $command_id),*
        }
        enum OpenWireCommandMarshaller {
            BaseCommand(BaseCommand),
            BaseDataStream(BaseDataStream),
            $($variant($struct_name)),*
        }
        $(
            #[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
            struct $struct_name {}
        )*
        #[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
        struct BaseCommand {}
        #[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
        struct BaseDataStream {}
        impl OpenWireCommandMarshaller {
            fn from(command: OpenWireCommand) -> Self {
                match command {
                    $(OpenWireCommand::$variant => OpenWireCommandMarshaller::$variant($struct_name{})),*
                }
            }
        }
        impl fmt::Display for OpenWireCommand {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(OpenWireCommand::$variant => write!(f, stringify!($variant))),*
                }
            }
        }
        impl TryFrom<u8> for OpenWireCommand {
            type Error = Error;
            fn try_from(value: u8) -> Result<Self> {
                match value {
                    $($command_id => Ok(OpenWireCommand::$variant)),*,
                    _ => Err(Error::OpenWireLogParseFailed)
                }
            }
        }
        impl From<OpenWireCommand> for u8 {
            fn from(command: OpenWireCommand) -> Self {
                match command {
                    $(OpenWireCommand::$variant => $command_id),*
                }
            }
        }
    };
}

all_openwire_commands!(
    WireFormatInfo(WireFormatInfo, 1),
    BrokerInfo(BrokerInfo, 2),
    ConnectionInfo(ConnectionInfo, 3),
    SessionInfo(SessionInfo, 4),
    ConsumerInfo(ConsumerInfo, 5),
    ProducerInfo(ProducerInfo, 6),
    TransactionInfo(TransactionInfo, 7),
    DestinationInfo(DestinationInfo, 8),
    RemoveSubscriptionInfo(RemoveSubscriptionInfo, 9),
    KeepAliveInfo(KeepAliveInfo, 10),
    ShutdownInfo(ShutdownInfo, 11),
    RemoveInfo(RemoveInfo, 12),
    ControlCommand(ControlCommand, 14),
    FlushCommand(FlushCommand, 15),
    ConnectionError(ConnectionError, 16),
    ConsumerControl(ConsumerControl, 17),
    ConnectionControl(ConnectionControl, 18),
    ProducerAck(ProducerAck, 19),
    MessagePull(MessagePull, 20),
    MessageDispatch(MessageDispatch, 21),
    MessageAck(MessageAck, 22),
    ActiveMQMessage(ActiveMQMessage, 23),
    ActiveMQBytesMessage(ActiveMQBytesMessage, 24),
    ActiveMQMapMessage(ActiveMQMapMessage, 25),
    ActiveMQObjectMessage(ActiveMQObjectMessage, 26),
    ActiveMQStreamMessage(ActiveMQStreamMessage, 27),
    ActiveMQTextMessage(ActiveMQTextMessage, 28),
    ActiveMQBlobMessage(ActiveMQBlobMessage, 29),
    Response(Response, 30),
    ExceptionResponse(ExceptionResponse, 31),
    DataResponse(DataResponse, 32),
    DataArrayResponse(DataArrayResponse, 33),
    IntegerResponse(IntegerResponse, 34),
    DiscoveryEvent(DiscoveryEvent, 40),
    JournalTopicAck(JournalTopicAck, 50),
    JournalQueueAck(JournalQueueAck, 52),
    JournalTrace(JournalTrace, 53),
    JournalTransaction(JournalTransaction, 54),
    DurableSubscriptionInfo(DurableSubscriptionInfo, 55),
    PartialCommand(PartialCommand, 60),
    PartialLastCommand(PartialLastCommand, 61),
    Replay(Replay, 65),
    ByteType(ByteType, 70),
    CharType(CharType, 71),
    ShortType(ShortType, 72),
    IntegerType(IntegerType, 73),
    LongType(LongType, 74),
    DoubleType(DoubleType, 75),
    FloatType(FloatType, 76),
    StringType(StringType, 77),
    BooleanType(BooleanType, 78),
    ByteArrayType(ByteArrayType, 79),
    MessageDispatchNotification(MessageDispatchNotification, 90),
    NetworkBridgeFilter(NetworkBridgeFilter, 91),
    ActiveMQQueue(ActiveMQQueue, 100),
    ActiveMQTopic(ActiveMQTopic, 101),
    ActiveMQTempQueue(ActiveMQTempQueue, 102),
    ActiveMQTempTopic(ActiveMQTempTopic, 103),
    MessageId(MessageId, 110),
    ActiveMQLocalTransactionId(ActiveMQLocalTransactionId, 111),
    ActiveMQXATransactionId(ActiveMQXATransactionId, 112),
    ConnectionId(ConnectionId, 120),
    SessionId(SessionId, 121),
    ConsumerId(ConsumerId, 122),
    ProducerId(ProducerId, 123),
    BrokerId(BrokerId, 124),
);

macro_rules! impl_auto_marshaller {
    ($($command_type:ident),* $(,)?) => {
        impl OpenWireCommandMarshaller {
            fn tight_unmarshal<'a>(
                &self,
                parser: &mut OpenWireLog,
                info: &mut OpenWireInfo,
                bs: &mut BooleanStream,
                payload: &'a [u8],
            ) -> Result<&'a [u8]> {
                match self {
                    $(OpenWireCommandMarshaller::$command_type(_) => {
                        $command_type::tight_unmarshal(parser, info, bs, payload)
                    })*
                    _ => Err(Error::OpenWireLogParseUnimplemented),
                }
            }
            fn loose_unmarshal<'a>(
                &self,
                parser: &mut OpenWireLog,
                info: &mut OpenWireInfo,
                payload: &'a [u8],
            ) -> Result<&'a [u8]> {
                match self {
                    $(OpenWireCommandMarshaller::$command_type(_) => {
                        $command_type::loose_unmarshal(parser, info, payload)
                    })*
                    _ => Err(Error::OpenWireLogParseUnimplemented),
                }
            }
            fn tight_unmarshal_command<'a>(
                &self,
                parser: &mut OpenWireLog,
                info: &mut OpenWireInfo,
                bs: &mut BooleanStream,
                payload: &'a [u8],
            ) -> Result<&'a [u8]> {
                match self {
                    $(OpenWireCommandMarshaller::$command_type(_) => {
                        $command_type::tight_unmarshal(parser, info, bs, payload)
                    })*
                    _ => {
                        BaseCommand::tight_unmarshal(parser, info, bs, payload)?;
                        Err(Error::OpenWireLogParseUnimplemented)
                    }
                }
            }
            fn loose_unmarshal_command<'a>(
                &self,
                parser: &mut OpenWireLog,
                info: &mut OpenWireInfo,
                payload: &'a [u8],
            ) -> Result<&'a [u8]> {
                match self {
                    $(OpenWireCommandMarshaller::$command_type(_) => {
                        $command_type::loose_unmarshal(parser, info, payload)
                    })*
                    _ => {
                        BaseCommand::loose_unmarshal(parser, info, payload)?;
                        Err(Error::OpenWireLogParseUnimplemented)
                    }
                }
            }
        }
    };
}

impl_auto_marshaller!(
    BaseCommand,
    WireFormatInfo,
    ConnectionInfo,
    SessionInfo,
    ConsumerInfo,
    ProducerInfo,
    BrokerInfo,
    ConnectionError,
    ActiveMQLocalTransactionId,
    ActiveMQXATransactionId,
    ConnectionId,
    SessionId,
    ConsumerId,
    ProducerId,
    BrokerId,
    MessageId,
    // topic and queue
    ActiveMQTopic,
    ActiveMQQueue,
    ActiveMQTempTopic,
    ActiveMQTempQueue,
    // message types
    ActiveMQMessage,
    ActiveMQBytesMessage,
    ActiveMQMapMessage,
    ActiveMQObjectMessage,
    ActiveMQStreamMessage,
    ActiveMQTextMessage,
    ActiveMQBlobMessage,
    // message pull, dispatch and ack
    MessageDispatch,
    MessageAck,
    // response
    Response,
    ExceptionResponse,
);

struct BooleanStream<'a> {
    payload: &'a [u8],
    offset: usize,
    bitpos: usize,
    // bytes consumed in payload (include the length)
    bytes_consumed: usize,
}

impl<'a> BooleanStream<'a> {
    fn new(payload: &'a [u8], bytes_consumed: usize) -> Self {
        BooleanStream {
            payload,
            offset: 0,
            bitpos: 0,
            bytes_consumed: bytes_consumed,
        }
    }
    fn read_bool(&mut self) -> Option<bool> {
        if self.offset >= self.payload.len() {
            return None;
        }
        let byte = self.payload[self.offset];
        let bit = (byte >> self.bitpos) & 1;
        self.bitpos += 1;
        if self.bitpos == 8 {
            self.offset += 1;
            self.bitpos = 0;
        }
        Some(bit == 1)
    }
    fn read_boolean_stream(payload: &'a [u8]) -> Result<(&'a [u8], Self)> {
        // read bollean stream length
        let (mut payload, byte) = parse_byte(payload)?;
        let mut bs_length = byte as usize;
        let mut length_len = 1;
        match bs_length {
            0xC0 => {
                let (new_payload, byte) = parse_byte(payload)?;
                bs_length = byte as usize;
                length_len += 1;
                payload = new_payload;
            }
            0x80 => {
                let (new_payload, short) = parse_short(payload)?;
                bs_length = short as usize;
                length_len += 2;
                payload = new_payload;
            }
            _ => {}
        }
        if bs_length == 0 {
            return Err(Error::OpenWireLogParseFailed);
        }
        // read boolean stream
        let (payload, bs) = parse_bytes(payload, bs_length)?;
        Ok((payload, Self::new(bs, length_len + bs_length)))
    }
}

fn parse_byte<'a>(payload: &'a [u8]) -> Result<(&'a [u8], u8)> {
    let (payload, byte) = number::complete::be_u8(payload)
        .map_err(|_: Err<error::Error<_>>| Error::OpenWireLogParseEOF)?;
    Ok((payload, byte))
}
fn parse_short<'a>(payload: &'a [u8]) -> Result<(&'a [u8], u16)> {
    let (payload, short) = number::complete::be_u16(payload)
        .map_err(|_: Err<error::Error<_>>| Error::OpenWireLogParseEOF)?;
    Ok((payload, short))
}
fn parse_integer<'a>(payload: &'a [u8]) -> Result<(&'a [u8], u32)> {
    let (payload, integer) = number::complete::be_u32(payload)
        .map_err(|_: Err<error::Error<_>>| Error::OpenWireLogParseEOF)?;
    Ok((payload, integer))
}
fn parse_long<'a>(payload: &'a [u8]) -> Result<(&'a [u8], u64)> {
    let (payload, long) = number::complete::be_u64(payload)
        .map_err(|_: Err<error::Error<_>>| Error::OpenWireLogParseEOF)?;
    Ok((payload, long))
}
fn parse_boolean<'a>(payload: &'a [u8]) -> Result<(&'a [u8], bool)> {
    let (payload, byte) = parse_byte(payload)?;
    let boolean = match byte {
        0 => false,
        _ => true,
    };
    Ok((payload, boolean))
}
fn parse_bytes<'a>(payload: &'a [u8], length: usize) -> Result<(&'a [u8], &'a [u8])> {
    let (payload, bytes) = bytes::complete::take(length)(payload)
        .map_err(|_: Err<error::Error<_>>| Error::OpenWireLogParseEOF)?;
    Ok((payload, bytes))
}
fn parse_command_type(payload: &[u8]) -> Result<(&[u8], OpenWireCommand)> {
    let (payload, command_type) = parse_byte(payload)?;
    let command_type = OpenWireCommand::try_from(command_type)?;
    Ok((payload, command_type))
}
fn parse_trace_and_span(
    payload: &[u8],
    config: &L7LogDynamicConfig,
) -> Result<(Option<String>, Option<String>)> {
    // header pattern: "<TraceType>\x09<length in short type><values>"
    // now only skywalking supports activemq
    let trace_type = TraceType::Sw8;
    let trace_parsable = config.trace_types.contains(&trace_type);
    let span_parsable = config.span_types.contains(&trace_type);
    if !span_parsable && !trace_parsable {
        return Ok((None, None));
    }
    let header_pattern = b"sw8\x09";
    let mut next_payload = payload;
    while next_payload.len() > header_pattern.len() {
        let payload = next_payload;
        // match header_pattern
        let payload = match payload
            .windows(header_pattern.len())
            .position(|window| window == header_pattern)
        {
            Some(index) => {
                next_payload = &payload[index + header_pattern.len()..];
                &payload[index + header_pattern.len()..]
            }
            None => break,
        };
        // parse values length
        let values = match parse_short(payload) {
            Ok((payload, length)) => payload
                .get(..length as usize)
                .ok_or(Error::OpenWireLogParseEOF)?,
            Err(_) => continue,
        };
        let values = match std::str::from_utf8(values) {
            Ok(values) => values,
            Err(_) => continue,
        };
        let trace_id = if trace_parsable {
            trace_type.decode_trace_id(values).map(|s| s.to_string())
        } else {
            None
        };
        let span_id = if span_parsable {
            trace_type.decode_span_id(values).map(|s| s.to_string())
        } else {
            None
        };
        return Ok((trace_id, span_id));
    }
    Err(Error::OpenWireLogParseFailed)
}

trait Unmarshal {
    #[allow(unused_variables)]
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        Err(Error::OpenWireLogParseFailed)
    }
    #[allow(unused_variables)]
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        Err(Error::OpenWireLogParseFailed)
    }
}

impl Unmarshal for BaseCommand {
    fn tight_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId
        let (payload, command_id) = parse_integer(payload)?;
        // command id is unlikely to be larger than 2^24
        if command_id > 0xffffff {
            return Err(Error::OpenWireLogParseFailed);
        }
        info.command_id = command_id;
        // parse responseRequired
        match bs.read_bool() {
            Some(boolean) => {
                info.response_required = boolean;
                Ok(payload)
            }
            None => Err(Error::OpenWireLogParseFailed),
        }
    }
    fn loose_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId
        let (payload, command_id) = parse_integer(payload)?;
        info.command_id = command_id;
        // command id is unlikely to be larger than 2^24
        if command_id > 0xffffff {
            return Err(Error::OpenWireLogParseFailed);
        }
        // parse responseRequired
        let (payload, boolean) = parse_boolean(payload)?;
        info.response_required = boolean;
        Ok(payload)
    }
}

impl BaseDataStream {
    fn tight_unmarshal_string<'a>(
        payload: &'a [u8],
        bs: &mut BooleanStream,
    ) -> Result<(&'a [u8], &'a str)> {
        match bs.read_bool() {
            Some(true) => match bs.read_bool() {
                Some(_) => {
                    let (payload, length) = parse_short(payload)?;
                    let (payload, string) = parse_bytes(payload, length as usize)?;
                    Ok((
                        payload,
                        std::str::from_utf8(string).map_err(|_| Error::OpenWireLogParseFailed)?,
                    ))
                }
                None => Err(Error::OpenWireLogParseFailed),
            },
            Some(false) => Ok((payload, "")),
            None => Err(Error::OpenWireLogParseFailed),
        }
    }
    fn loose_unmarshal_string<'a>(payload: &'a [u8]) -> Result<(&'a [u8], &'a str)> {
        let (payload, boolean) = parse_boolean(payload)?;
        match boolean {
            true => {
                let (payload, length) = parse_short(payload)?;
                let (payload, string) = parse_bytes(payload, length as usize)?;
                Ok((
                    payload,
                    std::str::from_utf8(string).map_err(|_| Error::OpenWireLogParseFailed)?,
                ))
            }
            false => Ok((payload, "")),
        }
    }
    fn tight_unmarshal_long<'a>(
        payload: &'a [u8],
        bs: &mut BooleanStream,
    ) -> Result<(&'a [u8], u64)> {
        if bs.read_bool().ok_or(Error::OpenWireLogParseFailed)? {
            if bs.read_bool().ok_or(Error::OpenWireLogParseFailed)? {
                let (payload, long) = parse_long(payload)?;
                Ok((payload, long))
            } else {
                let (payload, integer) = parse_integer(payload)?;
                Ok((payload, integer as u64))
            }
        } else {
            if bs.read_bool().ok_or(Error::OpenWireLogParseFailed)? {
                let (payload, long) = parse_short(payload)?;
                Ok((payload, long as u64))
            } else {
                Ok((payload, 0))
            }
        }
    }
    fn loose_unmarshal_long<'a>(payload: &'a [u8]) -> Result<(&'a [u8], u64)> {
        parse_long(payload)
    }
    fn tight_unmarshal_byte_array<'a>(
        payload: &'a [u8],
        bs: &mut BooleanStream,
    ) -> Result<(&'a [u8], Option<&'a [u8]>)> {
        match bs.read_bool() {
            Some(true) => {
                let (payload, length) = parse_integer(payload)?;
                let (payload, bytes) = parse_bytes(payload, length as usize)?;
                Ok((payload, Some(bytes)))
            }
            Some(false) => Ok((payload, None)),
            None => Err(Error::OpenWireLogParseFailed),
        }
    }
    fn loose_unmarshal_byte_array<'a>(payload: &'a [u8]) -> Result<(&'a [u8], Option<&'a [u8]>)> {
        match parse_boolean(payload)? {
            (payload, true) => {
                let (payload, length) = parse_integer(payload)?;
                let (payload, bytes) = parse_bytes(payload, length as usize)?;
                Ok((payload, Some(bytes)))
            }
            (payload, false) => Ok((payload, None)),
        }
    }
    fn tight_unmarshal_nested_object<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        match bs.read_bool() {
            Some(true) => {
                let (payload, data_type) = parse_byte(payload)?;
                let data_type = OpenWireCommand::try_from(data_type)?;
                // consume a boolean if is_marshall_aware is true
                if Self::is_marshall_aware(data_type) {
                    let _ = bs.read_bool().ok_or(Error::OpenWireLogParseFailed)?;
                }
                let data_marshaller = OpenWireCommandMarshaller::from(data_type);
                data_marshaller.tight_unmarshal(parser, info, bs, payload)
            }
            Some(false) => Ok(payload),
            None => Err(Error::OpenWireLogParseFailed),
        }
    }
    fn loose_unmarshal_nested_object<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        match parse_boolean(payload)? {
            (payload, true) => {
                let (payload, data_type) = parse_byte(payload)?;
                let data_type = OpenWireCommand::try_from(data_type)?;
                let data_marshaller = OpenWireCommandMarshaller::from(data_type);
                data_marshaller.loose_unmarshal(parser, info, payload)
            }
            (payload, false) => Ok(payload),
        }
    }
    fn tight_unmarshal_cached_object<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        if parser.is_cache_enabled {
            // cached object is not supported
            match bs.read_bool() {
                Some(true) => {
                    // parse cache index
                    let (payload, _) = parse_short(payload)?;
                    // parse object
                    Self::tight_unmarshal_nested_object(parser, info, bs, payload)
                }
                Some(false) => {
                    // parse cache index
                    let (payload, _) = parse_short(payload)?;
                    // cannot parse cached object
                    Ok(payload)
                }
                None => Err(Error::OpenWireLogParseFailed),
            }
        } else {
            Self::tight_unmarshal_nested_object(parser, info, bs, payload)
        }
    }
    fn loose_unmarshal_cached_object<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        if parser.is_cache_enabled {
            // cached object is not supported
            match parse_boolean(payload)? {
                (payload, true) => {
                    // parse cache index
                    let (payload, _) = parse_short(payload)?;
                    // parse object
                    Self::loose_unmarshal_nested_object(parser, info, payload)
                }
                (payload, false) => {
                    // parse cache index
                    let (payload, _) = parse_short(payload)?;
                    // cannot parse cached object
                    Ok(payload)
                }
            }
        } else {
            Self::loose_unmarshal_nested_object(parser, info, payload)
        }
    }
    fn tight_unmarshal_broker_error<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        match bs.read_bool() {
            Some(true) => {
                // parse exception class
                let (payload, _) = Self::tight_unmarshal_string(payload, bs)?;
                // parse exception message
                let (_, err_msg) = Self::tight_unmarshal_string(payload, bs)?;
                info.err_msg = Some(err_msg.to_string());
                Err(Error::OpenWireLogParseUnimplemented)
            }
            Some(false) => Ok(payload),
            None => Err(Error::OpenWireLogParseFailed),
        }
    }
    fn loose_unmarshal_broker_error<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        match parse_boolean(payload)? {
            (payload, true) => {
                // parse exception class
                let (payload, _) = Self::loose_unmarshal_string(payload)?;
                // parse exception message
                let (_, err_msg) = Self::loose_unmarshal_string(payload)?;
                info.err_msg = Some(err_msg.to_string());
                Err(Error::OpenWireLogParseUnimplemented)
            }
            (payload, false) => Ok(payload),
        }
    }
    fn is_marshall_aware(command_type: OpenWireCommand) -> bool {
        match command_type {
            // WireFormatInfo and ActiveMQMessage
            OpenWireCommand::WireFormatInfo
            | OpenWireCommand::ActiveMQMessage
            | OpenWireCommand::ActiveMQBytesMessage
            | OpenWireCommand::ActiveMQMapMessage
            | OpenWireCommand::ActiveMQObjectMessage
            | OpenWireCommand::ActiveMQStreamMessage
            | OpenWireCommand::ActiveMQTextMessage
            | OpenWireCommand::ActiveMQBlobMessage => true,
            _ => false,
        }
    }
}

impl Unmarshal for ActiveMQLocalTransactionId {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse transactionId
        let (payload, _) = BaseDataStream::tight_unmarshal_long(payload, bs)?;
        // parse connetionId
        BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse transactionId
        let (payload, _) = BaseDataStream::loose_unmarshal_long(payload)?;
        // parse connetionId
        BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)
    }
}

impl Unmarshal for ActiveMQXATransactionId {
    fn tight_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        _info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse formatId
        let (payload, _) = parse_integer(payload)?;
        // parse globalTransactionId
        // refer to JMS repo file path:
        // "openwire-legacy/src/main/java/org/apache/activemq/openwire/codec/v12/XATransactionIdMarshaller.java"
        // note that there may exist an unmarshal bug in the JMS repo in
        // "openwire-core/src/main/java/org/apache/activemq/openwire/codec/universal/XATransactionIdMarshaller.java"
        // we choose to follow the v12 implementation
        let (payload, _) = BaseDataStream::tight_unmarshal_byte_array(payload, bs)?;
        // parse branchQualifier
        let (payload, _) = BaseDataStream::tight_unmarshal_byte_array(payload, bs)?;
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        _info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse formatId
        let (payload, _) = parse_integer(payload)?;
        // parse globalTransactionId
        let (payload, _) = BaseDataStream::loose_unmarshal_byte_array(payload)?;
        // parse branchQualifier
        let (payload, _) = BaseDataStream::loose_unmarshal_byte_array(payload)?;
        Ok(payload)
    }
}

impl Unmarshal for ConnectionId {
    fn tight_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        let (payload, connection_id) = BaseDataStream::tight_unmarshal_string(payload, bs)?;
        info.connection_id = Some(connection_id.to_string());
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        let (payload, connection_id) = BaseDataStream::loose_unmarshal_string(payload)?;
        info.connection_id = Some(connection_id.to_string());
        Ok(payload)
    }
}

impl Unmarshal for SessionId {
    fn tight_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse connectionId
        let (payload, connection_id) = BaseDataStream::tight_unmarshal_string(payload, bs)?;
        info.connection_id = Some(connection_id.to_string());
        // parse sessionId
        let (payload, session_id) = BaseDataStream::tight_unmarshal_long(payload, bs)?;
        info.session_id = Some(session_id);
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse connectionId
        let (payload, connection_id) = BaseDataStream::loose_unmarshal_string(payload)?;
        info.connection_id = Some(connection_id.to_string());
        // parse sessionId
        let (payload, session_id) = BaseDataStream::loose_unmarshal_long(payload)?;
        info.session_id = Some(session_id);
        Ok(payload)
    }
}

impl Unmarshal for ConsumerId {
    fn tight_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse connectionId
        let (payload, connection_id) = BaseDataStream::tight_unmarshal_string(payload, bs)?;
        info.connection_id = Some(connection_id.to_string());
        // parse sessionId
        let (payload, session_id) = BaseDataStream::tight_unmarshal_long(payload, bs)?;
        info.session_id = Some(session_id);
        // parse consumerId
        let (payload, _) = BaseDataStream::tight_unmarshal_long(payload, bs)?;
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse connectionId
        let (payload, connection_id) = BaseDataStream::loose_unmarshal_string(payload)?;
        info.connection_id = Some(connection_id.to_string());
        // parse sessionId
        let (payload, session_id) = BaseDataStream::loose_unmarshal_long(payload)?;
        info.session_id = Some(session_id);
        // parse consumerId
        let (payload, _) = BaseDataStream::loose_unmarshal_long(payload)?;
        Ok(payload)
    }
}

impl Unmarshal for ProducerId {
    // note that the parsing order is distinct from ConsumerId
    fn tight_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse connectionId
        let (payload, connection_id) = BaseDataStream::tight_unmarshal_string(payload, bs)?;
        info.connection_id = Some(connection_id.to_string());
        // parse producerId
        let (payload, _) = BaseDataStream::tight_unmarshal_long(payload, bs)?;
        // parse sessionId
        let (payload, session_id) = BaseDataStream::tight_unmarshal_long(payload, bs)?;
        info.session_id = Some(session_id);
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse connectionId
        let (payload, connection_id) = BaseDataStream::loose_unmarshal_string(payload)?;
        info.connection_id = Some(connection_id.to_string());
        // parse producerId
        let (payload, _) = BaseDataStream::loose_unmarshal_long(payload)?;
        // parse sessionId
        let (payload, session_id) = BaseDataStream::loose_unmarshal_long(payload)?;
        info.session_id = Some(session_id);
        Ok(payload)
    }
}

impl Unmarshal for MessageId {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        mut payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse textView
        if parser.version >= 10 {
            let (updated_payload, _) = BaseDataStream::tight_unmarshal_string(payload, bs)?;
            payload = updated_payload;
        }
        // parse producerId
        let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // parse producerSequenceId
        let (payload, _) = BaseDataStream::tight_unmarshal_long(payload, bs)?;
        // parse brokerSequenceId
        let (payload, _) = BaseDataStream::tight_unmarshal_long(payload, bs)?;
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        mut payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse textView
        if parser.version >= 10 {
            let (updated_payload, _) = BaseDataStream::loose_unmarshal_string(payload)?;
            payload = updated_payload;
        }
        // parse producerId
        let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        // parse producerSequenceId
        let (payload, _) = BaseDataStream::loose_unmarshal_long(payload)?;
        // parse brokerSequenceId
        let (payload, _) = BaseDataStream::loose_unmarshal_long(payload)?;
        Ok(payload)
    }
}

impl Unmarshal for BrokerId {
    fn tight_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        _info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse brokerId
        let (payload, _) = BaseDataStream::tight_unmarshal_string(payload, bs)?;
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        _info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse brokerId
        let (payload, _) = BaseDataStream::loose_unmarshal_string(payload)?;
        Ok(payload)
    }
}

impl Unmarshal for ConnectionInfo {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::tight_unmarshal(parser, info, bs, payload)?;
        // parse connectionId
        let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // parse clientId
        let _ = BaseDataStream::tight_unmarshal_string(payload, bs)?;
        // TODO: more fields are not supported
        Err(Error::OpenWireLogParseUnimplemented)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::loose_unmarshal(parser, info, payload)?;
        // parse connectionId
        let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        // parse clientId
        let _ = BaseDataStream::loose_unmarshal_string(payload)?;
        // TODO: more fields are not supported
        Err(Error::OpenWireLogParseUnimplemented)
    }
}

impl Unmarshal for SessionInfo {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::tight_unmarshal(parser, info, bs, payload)?;
        // parse sessionId
        let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::loose_unmarshal(parser, info, payload)?;
        // parse sessionId
        let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        Ok(payload)
    }
}

impl Unmarshal for ConsumerInfo {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::tight_unmarshal(parser, info, bs, payload)?;
        // parse consumerId
        let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // parse browser
        let _ = bs.read_bool().ok_or(Error::OpenWireLogParseFailed)?;
        // parse destination
        let _ = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // TODO: more fields are not supported
        Err(Error::OpenWireLogParseUnimplemented)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::loose_unmarshal(parser, info, payload)?;
        // parse consumerId
        let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        // parse browser
        let _ = parse_boolean(payload)?;
        // parse destination
        let _ = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        // TODO: more fields are not supported
        Err(Error::OpenWireLogParseUnimplemented)
    }
}

impl Unmarshal for ProducerInfo {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::tight_unmarshal(parser, info, bs, payload)?;
        // parse producerId
        let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // parse destination
        let _ = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // TODO: more fields are not supported
        Err(Error::OpenWireLogParseUnimplemented)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::loose_unmarshal(parser, info, payload)?;
        // parse producerId
        let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        // parse destination
        let _ = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        // TODO: more fields are not supported
        Err(Error::OpenWireLogParseUnimplemented)
    }
}

impl Unmarshal for BrokerInfo {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::tight_unmarshal(parser, info, bs, payload)?;
        // parse brokerId
        let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // parse brokerURL
        let (_, broker_url) = BaseDataStream::tight_unmarshal_string(payload, bs)?;
        info.broker_url = Some(broker_url.to_string());
        Err(Error::OpenWireLogParseUnimplemented)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::loose_unmarshal(parser, info, payload)?;
        // parse brokerId
        let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        // parse brokerURL
        let (_, broker_url) = BaseDataStream::loose_unmarshal_string(payload)?;
        info.broker_url = Some(broker_url.to_string());
        Err(Error::OpenWireLogParseUnimplemented)
    }
}

impl Unmarshal for WireFormatInfo {
    // we do not implement tight_unmarshal for WireFormatInfo
    // since it is the first message in the log and the
    // tight_encoding flag is not negotiated yet
    fn loose_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse magic field "ActiveMQ"
        let (payload, magic) = parse_bytes(payload, 8usize)?;
        match std::str::from_utf8(magic) {
            Ok(magic) => {
                if magic != "ActiveMQ" {
                    return Err(Error::OpenWireLogParseFailed);
                }
            }
            _ => {
                return Err(Error::OpenWireLogParseFailed);
            }
        }

        // parse version
        let (payload, version) = parse_integer(payload)?;
        info.version = version;

        // parse mapping
        let (payload, is_null) = parse_byte(payload)?;
        if is_null == 0 {
            return Ok(payload);
        }
        let (payload, length) = parse_integer(payload)?;

        // parse TightEncodingEnabled
        // pattern: "TightEncodingEnabled\x01", where \x01 refers to a boolean type
        // marshalPrimitiveMap in openwire-core/src/main/java/org/apache/activemq/openwire/utils/OpenWireMarshallingSupport.java
        // NULL = 0;
        // BOOLEAN_TYPE = 1;
        // BYTE_TYPE = 2;
        // CHAR_TYPE = 3;
        // SHORT_TYPE = 4;
        // INTEGER_TYPE = 5;
        // LONG_TYPE = 6;
        // DOUBLE_TYPE = 7;
        // FLOAT_TYPE = 8;
        // STRING_TYPE = 9;
        // BYTE_ARRAY_TYPE = 10;
        // MAP_TYPE = 11;
        // LIST_TYPE = 12;
        // BIG_STRING_TYPE = 13;
        let key = "TightEncodingEnabled\x01".as_bytes();
        if let Some(index) = payload.windows(key.len()).position(|window| window == key) {
            match payload.get(index + key.len()) {
                Some(value) => {
                    let boolean = value != &0;
                    info.is_tight_encoding_enabled = boolean;
                }
                _ => return Err(Error::OpenWireLogParseEOF),
            }
        }

        // parse SizePrefixDisabled
        let key = "SizePrefixDisabled\x01".as_bytes();
        if let Some(index) = payload.windows(key.len()).position(|window| window == key) {
            match payload.get(index + key.len()) {
                Some(value) => {
                    let boolean = value != &0;
                    info.is_size_prefix_disabled = boolean;
                }
                _ => return Err(Error::OpenWireLogParseEOF),
            }
        }

        // parse CacheEnabled
        let key = "CacheEnabled\x01".as_bytes();
        if let Some(index) = payload.windows(key.len()).position(|window| window == key) {
            match payload.get(index + key.len()) {
                Some(value) => {
                    let boolean = value != &0;
                    info.is_cache_enabled = boolean;
                }
                _ => return Err(Error::OpenWireLogParseEOF),
            }
        }

        // take the rest of payload
        let (payload, _) = parse_bytes(payload, length as usize)?;
        Ok(payload)
    }
}

impl Unmarshal for ConnectionError {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::tight_unmarshal(parser, info, bs, payload)?;
        // parse exception
        let payload = BaseDataStream::tight_unmarshal_broker_error(parser, info, bs, payload)?;
        // parse connectionId
        let payload = BaseDataStream::tight_unmarshal_nested_object(parser, info, bs, payload)?;
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::loose_unmarshal(parser, info, payload)?;
        // parse exception
        let payload = BaseDataStream::loose_unmarshal_broker_error(parser, info, payload)?;
        // parse connectionId
        let payload = BaseDataStream::loose_unmarshal_nested_object(parser, info, payload)?;
        Ok(payload)
    }
}

impl Unmarshal for MessageDispatch {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::tight_unmarshal(parser, info, bs, payload)?;
        // parse destination
        let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // parse consumerId
        let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // parse message
        let payload = BaseDataStream::tight_unmarshal_nested_object(parser, info, bs, payload)?;
        // parse redeliveryCounter
        let (payload, _) = parse_integer(payload)?;
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::loose_unmarshal(parser, info, payload)?;
        // parse destination
        let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        // parse consumerId
        let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        // parse message
        let _ = BaseDataStream::loose_unmarshal_nested_object(parser, info, payload)?;
        // parse redeliveryCounter
        let (payload, _) = parse_integer(payload)?;
        Ok(payload)
    }
}

impl Unmarshal for MessageAck {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::tight_unmarshal(parser, info, bs, payload)?;
        // parse destination
        let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // parse transactionId
        let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // parse consumerId
        let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // parse ackType
        let (payload, _) = parse_byte(payload)?;
        // parse firstMessageId
        let payload = BaseDataStream::tight_unmarshal_nested_object(parser, info, bs, payload)?;
        // parse lastMessageId
        let payload = BaseDataStream::tight_unmarshal_nested_object(parser, info, bs, payload)?;
        // parse messageCount
        let (mut payload, _) = parse_integer(payload)?;
        // parse poisonCause
        if parser.version >= 7 {
            payload = BaseDataStream::tight_unmarshal_broker_error(parser, info, bs, payload)?;
        }
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::loose_unmarshal(parser, info, payload)?;
        // parse destination
        let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        // parse transactionId
        let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        // parse consumerId
        let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        // parse ackType
        let (payload, _) = parse_byte(payload)?;
        // parse firstMessageId
        let payload = BaseDataStream::loose_unmarshal_nested_object(parser, info, payload)?;
        // parse lastMessageId
        let payload = BaseDataStream::loose_unmarshal_nested_object(parser, info, payload)?;
        // parse messageCount
        let (mut payload, _) = parse_integer(payload)?;
        // parse poisonCause
        if parser.version >= 7 {
            payload = BaseDataStream::loose_unmarshal_broker_error(parser, info, payload)?;
        }
        Ok(payload)
    }
}

impl Unmarshal for Response {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::tight_unmarshal(parser, info, bs, payload)?;
        // parse correlationId
        let (payload, correlation_id) = parse_integer(payload)?;
        info.resp_command_id = correlation_id;
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse commandId and responseRequired
        let payload = BaseCommand::loose_unmarshal(parser, info, payload)?;
        // parse correlationId
        let (payload, correlation_id) = parse_integer(payload)?;
        info.resp_command_id = correlation_id;
        Ok(payload)
    }
}

impl Unmarshal for ExceptionResponse {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse response
        let payload = Response::tight_unmarshal(parser, info, bs, payload)?;
        // parse exception
        let payload = BaseDataStream::tight_unmarshal_broker_error(parser, info, bs, payload)?;
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse response
        let payload = Response::loose_unmarshal(parser, info, payload)?;
        // parse exception
        let payload = BaseDataStream::loose_unmarshal_broker_error(parser, info, payload)?;
        Ok(payload)
    }
}

impl Unmarshal for DataResponse {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse response
        let payload = Response::tight_unmarshal(parser, info, bs, payload)?;
        // parse data
        let payload = BaseDataStream::tight_unmarshal_nested_object(parser, info, bs, payload)?;
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse response
        let payload = Response::loose_unmarshal(parser, info, payload)?;
        // parse data
        let payload = BaseDataStream::loose_unmarshal_nested_object(parser, info, payload)?;
        Ok(payload)
    }
}

impl Unmarshal for DataArrayResponse {
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse response
        let payload = Response::tight_unmarshal(parser, info, bs, payload)?;
        // parse data array
        if bs.read_bool().ok_or(Error::OpenWireLogParseFailed)? {
            let (mut payload, length) = parse_short(payload)?;
            for _ in 0..length {
                payload = BaseDataStream::tight_unmarshal_nested_object(parser, info, bs, payload)?;
            }
            Ok(payload)
        } else {
            Ok(payload)
        }
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse response
        let payload = Response::loose_unmarshal(parser, info, payload)?;
        // parse data array
        let (payload, boolean) = parse_boolean(payload)?;
        if boolean {
            let (mut payload, length) = parse_short(payload)?;
            for _ in 0..length {
                payload = BaseDataStream::loose_unmarshal_nested_object(parser, info, payload)?;
            }
            Ok(payload)
        } else {
            Ok(payload)
        }
    }
}

macro_rules! impl_message_marshaller {
    ($($t:ty),+) => {
        $(impl Unmarshal for $t {
            fn tight_unmarshal<'a>(
                parser: &mut OpenWireLog,
                info: &mut OpenWireInfo,
                bs: &mut BooleanStream,
                payload: &'a [u8],
            ) -> Result<&'a [u8]> {
                // parse commandId and responseRequired
                let payload = BaseCommand::tight_unmarshal(parser, info, bs, payload)?;
                // parse producerId
                let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
                // parse destination
                let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
                // parse transactionId
                let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
                // parse originalDestination
                let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
                // parse messageId
                let payload = BaseDataStream::tight_unmarshal_nested_object(parser, info, bs, payload)?;
                // parse originalTransactionId
                let payload = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
                // parse groupID
                let (payload, _) = BaseDataStream::tight_unmarshal_string(payload, bs)?;
                // parse groupSequence
                let (payload, _) = parse_integer(payload)?;
                // parse correlationId
                let (_, correlation_id) = BaseDataStream::tight_unmarshal_string(payload, bs)?;
                info.correlation_id = (!correlation_id.is_empty()).then(|| correlation_id.to_string());
                Err(Error::OpenWireLogParseUnimplemented)
            }
            fn loose_unmarshal<'a>(
                parser: &mut OpenWireLog,
                info: &mut OpenWireInfo,
                payload: &'a [u8],
            ) -> Result<&'a [u8]> {
                // parse commandId and responseRequired
                let payload = BaseCommand::loose_unmarshal(parser, info, payload)?;
                // parse producerId
                let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
                // parse destination
                let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
                // parse transactionId
                let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
                // parse originalDestination
                let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
                // parse messageId
                let payload = BaseDataStream::loose_unmarshal_nested_object(parser, info, payload)?;
                // parse originalTransactionId
                let payload = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
                // parse groupID
                let (payload, _) = BaseDataStream::loose_unmarshal_string(payload)?;
                // parse groupSequence
                let (payload, _) = parse_integer(payload)?;
                // parse correlationId
                let (_, correlation_id) = BaseDataStream::loose_unmarshal_string(payload)?;
                info.correlation_id = (!correlation_id.is_empty()).then(|| correlation_id.to_string());
                Err(Error::OpenWireLogParseUnimplemented)
            }
        })*
    }
}
impl_message_marshaller!(
    ActiveMQMessage,
    ActiveMQBytesMessage,
    ActiveMQMapMessage,
    ActiveMQObjectMessage,
    ActiveMQStreamMessage,
    ActiveMQTextMessage,
    ActiveMQBlobMessage
);

macro_rules! impl_topic_marshaller {
    ($($t:ty),+) => {
        $(impl Unmarshal for $t {
            fn tight_unmarshal<'a>(
                _parser: &mut OpenWireLog,
                info: &mut OpenWireInfo,
                bs: &mut BooleanStream,
                payload: &'a [u8],
            ) -> Result<&'a [u8]> {
                // parse topic string
                let (paydload, topic) = BaseDataStream::tight_unmarshal_string(payload, bs)?;
                info.topic = Some(topic.to_string());
                Ok(paydload)
            }
            fn loose_unmarshal<'a>(
                _parser: &mut OpenWireLog,
                info: &mut OpenWireInfo,
                payload: &'a [u8],
            ) -> Result<&'a [u8]> {
                // parse topic string
                let (paydload, topic) = BaseDataStream::loose_unmarshal_string(payload)?;
                info.topic = Some(topic.to_string());
                Ok(paydload)
            }
        })*
    }
}
impl_topic_marshaller!(
    ActiveMQTopic,
    ActiveMQTempTopic,
    ActiveMQTempQueue,
    ActiveMQQueue
);

#[derive(Serialize, Clone, Debug)]
pub struct OpenWireInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,
    #[serde(skip)]
    direction: PacketDirection,

    is_tight_encoding_enabled: bool,
    is_size_prefix_disabled: bool,
    is_cache_enabled: bool,

    #[serde(skip_serializing_if = "value_is_default")]
    pub version: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,

    pub command_type: OpenWireCommand,
    pub command_id: u32,
    pub response_required: bool,
    pub resp_command_id: u32,

    #[serde(rename = "request_length", skip_serializing_if = "value_is_negative")]
    pub req_msg_size: Option<u32>,
    #[serde(rename = "response_length", skip_serializing_if = "value_is_negative")]
    pub res_msg_size: Option<u32>,

    pub status: L7ResponseStatus,
    pub err_msg: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,

    rtt: u64,
}

impl Default for OpenWireInfo {
    fn default() -> Self {
        OpenWireInfo {
            msg_type: Default::default(),
            is_tls: false,
            direction: PacketDirection::ClientToServer,
            is_tight_encoding_enabled: DEFAULT_TIGHT_ENCODING_ENABLED,
            is_size_prefix_disabled: DEFAULT_SIZE_PREFIX_DISABLED,
            is_cache_enabled: DEFAULT_CACHE_ENABLED,
            version: 0,
            connection_id: None,
            broker_url: None,
            session_id: None,
            topic: None,
            command_type: OpenWireCommand::WireFormatInfo,
            command_id: 0,
            response_required: false,
            resp_command_id: 0,
            req_msg_size: None,
            res_msg_size: None,
            status: L7ResponseStatus::Ok,
            err_msg: None,
            trace_id: None,
            span_id: None,
            correlation_id: None,
            rtt: 0,
        }
    }
}

impl OpenWireInfo {
    fn get_msg_size(&self) -> Option<u32> {
        match self.msg_type {
            LogMessageType::Request => self.req_msg_size,
            LogMessageType::Response => self.res_msg_size,
            LogMessageType::Session => {
                if self.direction == PacketDirection::ClientToServer {
                    self.req_msg_size
                } else {
                    self.res_msg_size
                }
            }
            _ => None,
        }
    }
    fn merge(&mut self, res: &Self) {
        if self.res_msg_size.is_none() {
            self.res_msg_size = res.res_msg_size;
        }
        if self.status == L7ResponseStatus::Ok {
            self.status = res.status;
            self.err_msg = res.err_msg.clone();
        }
    }
}

impl L7ProtocolInfoInterface for OpenWireInfo {
    fn session_id(&self) -> Option<u32> {
        match self.msg_type {
            LogMessageType::Request => Some(self.command_id),
            LogMessageType::Response => Some(self.resp_command_id),
            _ => None,
        }
    }
    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::OpenWireInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }
    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::OpenWire,
            msg_type: self.msg_type,
            rrt: self.rtt,
        })
    }
    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn get_request_domain(&self) -> String {
        self.broker_url.clone().unwrap_or_default()
    }
    fn get_endpoint(&self) -> Option<String> {
        self.topic.clone()
    }
}

impl From<OpenWireInfo> for L7ProtocolSendLog {
    fn from(f: OpenWireInfo) -> Self {
        let flags = if f.is_tls {
            EbpfFlags::TLS.bits()
        } else {
            EbpfFlags::NONE.bits()
        };
        L7ProtocolSendLog {
            req_len: f.req_msg_size,
            resp_len: f.res_msg_size,
            row_effect: 0,
            req: L7Request {
                req_type: f.command_type.to_string(),
                domain: f.broker_url.unwrap_or_default(),
                resource: f.topic.clone().unwrap_or_default(),
                endpoint: f.topic.unwrap_or_default(),
            },
            resp: L7Response {
                status: f.status,
                exception: f.err_msg.unwrap_or_default(),
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: f.trace_id,
                span_id: f.span_id,
                ..Default::default()
            }),
            version: Some(f.version.to_string()),
            flags,
            ext_info: match f.direction {
                PacketDirection::ClientToServer => Some(ExtendedInfo {
                    request_id: Some(f.command_id),
                    x_request_id_0: f.correlation_id,
                    ..Default::default()
                }),
                PacketDirection::ServerToClient => Some(ExtendedInfo {
                    request_id: Some(f.command_id),
                    x_request_id_1: f.correlation_id,
                    ..Default::default()
                }),
            },
            ..Default::default()
        }
    }
}

const DEFAULT_TIGHT_ENCODING_ENABLED: bool = true;
const DEFAULT_SIZE_PREFIX_DISABLED: bool = false;
const DEFAULT_CACHE_ENABLED: bool = true;
const DEFAULT_VERSION: u32 = 12;

bitflags! {
    struct WireFormatFlags: u8 {
        const TIGHT_ENCODING_ENABLED = 0b0000_0001;
        const SIZE_PREFIX_DISABLED = 0b0000_0010;
        const CACHE_ENABLED = 0b0000_0100;
        const DEFAULT = Self::TIGHT_ENCODING_ENABLED.bits | Self::CACHE_ENABLED.bits;
    }
}

impl Default for WireFormatFlags {
    fn default() -> Self {
        WireFormatFlags::DEFAULT
    }
}

pub struct OpenWireLog {
    client_wireformat_flags: Option<WireFormatFlags>,
    server_wireformat_flags: Option<WireFormatFlags>,
    is_tight_encoding_enabled: bool,
    is_size_prefix_disabled: bool,
    is_cache_enabled: bool,
    client_version: Option<u32>,
    server_version: Option<u32>,
    version: u32,

    client_next_skip_len: Option<usize>,
    server_next_skip_len: Option<usize>,
    perf_stats: Option<L7PerfStats>,
}

impl Default for OpenWireLog {
    fn default() -> Self {
        OpenWireLog {
            client_wireformat_flags: None,
            server_wireformat_flags: None,
            is_tight_encoding_enabled: DEFAULT_TIGHT_ENCODING_ENABLED,
            is_size_prefix_disabled: DEFAULT_SIZE_PREFIX_DISABLED,
            is_cache_enabled: DEFAULT_CACHE_ENABLED,
            client_version: None,
            server_version: None,
            version: DEFAULT_VERSION,
            client_next_skip_len: None,
            server_next_skip_len: None,
            perf_stats: None,
        }
    }
}

impl L7ProtocolParserInterface for OpenWireLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        Self::check_protocol(payload, param)
    }
    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let mut infos = self.parse(payload, param);

        infos.iter_mut().for_each(|info| {
            let info = match info {
                L7ProtocolInfo::OpenWireInfo(info) => info,
                _ => return,
            };
            if info.msg_type != LogMessageType::Session {
                info.cal_rrt(param, None).map(|rtt| {
                    info.rtt = rtt;
                    self.perf_stats.as_mut().map(|p| p.update_rrt(rtt));
                });
            }

            match param.direction {
                PacketDirection::ClientToServer => {
                    self.perf_stats.as_mut().map(|p| p.inc_req());
                }
                PacketDirection::ServerToClient => {
                    self.perf_stats.as_mut().map(|p| p.inc_resp());
                }
            }
        });

        if !param.parse_log {
            Ok(L7ParseResult::None)
        } else if infos.len() == 1 {
            Ok(L7ParseResult::Single(infos.pop().unwrap()))
        } else if infos.len() > 1 {
            Ok(L7ParseResult::Multi(infos))
        } else {
            Ok(L7ParseResult::None)
        }
    }
    fn protocol(&self) -> L7Protocol {
        L7Protocol::OpenWire
    }
    fn parsable_on_udp(&self) -> bool {
        false
    }
    fn reset(&mut self) {
        self.perf_stats = None;
    }
    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl OpenWireLog {
    fn is_message_type_valid(command_type: OpenWireCommand) -> bool {
        match command_type {
            OpenWireCommand::WireFormatInfo
            | OpenWireCommand::BrokerInfo
            | OpenWireCommand::ConnectionInfo
            | OpenWireCommand::SessionInfo
            | OpenWireCommand::ConsumerInfo
            | OpenWireCommand::ProducerInfo
            | OpenWireCommand::TransactionInfo
            | OpenWireCommand::DestinationInfo
            | OpenWireCommand::RemoveSubscriptionInfo
            | OpenWireCommand::KeepAliveInfo
            | OpenWireCommand::ShutdownInfo
            | OpenWireCommand::RemoveInfo
            | OpenWireCommand::ControlCommand
            | OpenWireCommand::FlushCommand
            | OpenWireCommand::ConnectionError
            | OpenWireCommand::ConsumerControl
            | OpenWireCommand::ConnectionControl
            | OpenWireCommand::ProducerAck
            | OpenWireCommand::MessagePull
            | OpenWireCommand::MessageDispatch
            | OpenWireCommand::MessageAck
            | OpenWireCommand::ActiveMQMessage
            | OpenWireCommand::ActiveMQBytesMessage
            | OpenWireCommand::ActiveMQMapMessage
            | OpenWireCommand::ActiveMQObjectMessage
            | OpenWireCommand::ActiveMQStreamMessage
            | OpenWireCommand::ActiveMQTextMessage
            | OpenWireCommand::ActiveMQBlobMessage
            | OpenWireCommand::DiscoveryEvent
            | OpenWireCommand::DurableSubscriptionInfo
            | OpenWireCommand::PartialCommand
            | OpenWireCommand::PartialLastCommand
            | OpenWireCommand::Replay
            | OpenWireCommand::MessageDispatchNotification
            | OpenWireCommand::Response
            | OpenWireCommand::ExceptionResponse
            | OpenWireCommand::DataResponse
            | OpenWireCommand::DataArrayResponse
            | OpenWireCommand::IntegerResponse => true,
            _ => false,
        }
    }
    fn do_unmarshal<'a>(
        &mut self,
        info: &mut OpenWireInfo,
        mut payload: &'a [u8],
        param: &ParseParam,
    ) -> Result<&'a [u8]> {
        let original_len = payload.len();
        let mut msg_size = payload.len();
        if !self.is_size_prefix_disabled {
            let (updated_payload, length) = parse_integer(payload)?;
            msg_size = length as usize;
            // message size is unlikely to be larger than 2^24
            if msg_size > 0xffffff {
                return Err(Error::OpenWireLogParseFailed);
            }
            payload = updated_payload;
        }
        // parse commandtype
        let (payload, command_type) = parse_command_type(payload)?;
        info.command_type = command_type;

        match command_type {
            OpenWireCommand::WireFormatInfo
            | OpenWireCommand::BrokerInfo
            | OpenWireCommand::ConnectionInfo
            | OpenWireCommand::SessionInfo
            | OpenWireCommand::ConsumerInfo
            | OpenWireCommand::ProducerInfo
            | OpenWireCommand::TransactionInfo
            | OpenWireCommand::DestinationInfo
            | OpenWireCommand::RemoveSubscriptionInfo
            | OpenWireCommand::KeepAliveInfo
            | OpenWireCommand::ShutdownInfo
            | OpenWireCommand::RemoveInfo
            | OpenWireCommand::ControlCommand
            | OpenWireCommand::FlushCommand
            | OpenWireCommand::ConnectionError
            | OpenWireCommand::ConsumerControl
            | OpenWireCommand::ConnectionControl
            | OpenWireCommand::ProducerAck
            | OpenWireCommand::MessagePull
            | OpenWireCommand::MessageDispatch
            | OpenWireCommand::MessageAck
            | OpenWireCommand::ActiveMQMessage
            | OpenWireCommand::ActiveMQBytesMessage
            | OpenWireCommand::ActiveMQMapMessage
            | OpenWireCommand::ActiveMQObjectMessage
            | OpenWireCommand::ActiveMQStreamMessage
            | OpenWireCommand::ActiveMQTextMessage
            | OpenWireCommand::ActiveMQBlobMessage
            | OpenWireCommand::DiscoveryEvent
            | OpenWireCommand::DurableSubscriptionInfo
            | OpenWireCommand::PartialCommand
            | OpenWireCommand::PartialLastCommand
            | OpenWireCommand::Replay
            | OpenWireCommand::MessageDispatchNotification => {
                info.msg_type = LogMessageType::Request;
                info.req_msg_size = Some(msg_size as u32);
                // parse sw8 trace_id and span_id
                if let Some(config) = param.parse_config {
                    (info.trace_id, info.span_id) =
                        parse_trace_and_span(payload, &config.l7_log_dynamic).unwrap_or_default();
                }
            }
            OpenWireCommand::Response
            | OpenWireCommand::ExceptionResponse
            | OpenWireCommand::DataResponse
            | OpenWireCommand::DataArrayResponse
            | OpenWireCommand::IntegerResponse => {
                info.msg_type = LogMessageType::Response;
                info.res_msg_size = Some(msg_size as u32);
            }
            _ => return Err(Error::OpenWireLogParseFailed),
        };

        let p = if self.is_tight_encoding_enabled && command_type != OpenWireCommand::WireFormatInfo
        {
            let (payload, mut bs) = BooleanStream::read_boolean_stream(payload)?;
            if !self.is_size_prefix_disabled && bs.bytes_consumed + 1 > msg_size {
                return Err(Error::OpenWireLogParseFailed);
            }
            let data_marshaller = OpenWireCommandMarshaller::from(command_type);
            data_marshaller.tight_unmarshal_command(self, info, &mut bs, payload)?
        } else {
            let data_marshaller = OpenWireCommandMarshaller::from(command_type);
            data_marshaller.loose_unmarshal_command(self, info, payload)?
        };
        // check if the payload length is valid
        if !self.is_size_prefix_disabled && original_len - p.len() != msg_size + 4 {
            return Err(Error::OpenWireLogParseFailed);
        }
        Ok(p)
    }
    fn parse_one<'a>(
        &mut self,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
        param: &ParseParam,
    ) -> Result<&'a [u8]> {
        let result = match self.do_unmarshal(info, payload, param) {
            Ok(p) => Ok(p),
            Err(Error::OpenWireLogParseUnimplemented) => Err(Error::OpenWireLogParseUnimplemented),
            Err(Error::OpenWireLogParseEOF) => Err(Error::OpenWireLogParseEOF),
            Err(e) => return Err(e),
        };
        info.is_tls = param.is_tls();
        info.direction = param.direction;
        // set status
        if info.err_msg.is_some() {
            if param.direction == PacketDirection::ClientToServer {
                info.status = L7ResponseStatus::ClientError;
            } else {
                info.status = L7ResponseStatus::ServerError;
            }
        }
        // set oneway request as session
        if info.msg_type == LogMessageType::Request && !info.response_required {
            info.msg_type = LogMessageType::Session;
            if param.direction == PacketDirection::ServerToClient {
                info.res_msg_size = info.req_msg_size.take();
            }
        }
        if info.command_type == OpenWireCommand::WireFormatInfo {
            // update version
            if param.direction == PacketDirection::ClientToServer {
                self.client_version = Some(info.version);
            } else {
                self.server_version = Some(info.version);
            }
            if let Some(client_version) = self.client_version {
                if let Some(server_version) = self.server_version {
                    self.version = client_version.min(server_version);
                }
            }

            // update wireformat flags
            let mut wireformat_flags = WireFormatFlags::default();
            wireformat_flags.set(
                WireFormatFlags::TIGHT_ENCODING_ENABLED,
                info.is_tight_encoding_enabled,
            );
            wireformat_flags.set(
                WireFormatFlags::SIZE_PREFIX_DISABLED,
                info.is_size_prefix_disabled,
            );
            wireformat_flags.set(WireFormatFlags::CACHE_ENABLED, info.is_cache_enabled);
            if param.direction == PacketDirection::ClientToServer {
                self.client_wireformat_flags = Some(wireformat_flags);
            } else {
                self.server_wireformat_flags = Some(wireformat_flags);
            }
            if let Some(client_wireformat_flags) = self.client_wireformat_flags {
                if let Some(server_wireformat_flags) = self.server_wireformat_flags {
                    let negotiated_wireformat_flags =
                        client_wireformat_flags & server_wireformat_flags;
                    self.is_tight_encoding_enabled = negotiated_wireformat_flags
                        .contains(WireFormatFlags::TIGHT_ENCODING_ENABLED);
                    self.is_size_prefix_disabled =
                        negotiated_wireformat_flags.contains(WireFormatFlags::SIZE_PREFIX_DISABLED);
                    self.is_cache_enabled =
                        negotiated_wireformat_flags.contains(WireFormatFlags::CACHE_ENABLED);
                }
            }
        } else {
            info.version = self.version;
            info.is_tight_encoding_enabled = self.is_tight_encoding_enabled;
            info.is_size_prefix_disabled = self.is_size_prefix_disabled;
            info.is_cache_enabled = self.is_cache_enabled;
        }
        result
    }
    fn parse(&mut self, mut payload: &[u8], param: &ParseParam) -> Vec<L7ProtocolInfo> {
        let mut infos = Vec::new();
        let mut current_skip_len = if param.direction == PacketDirection::ClientToServer {
            self.client_next_skip_len.take()
        } else {
            self.server_next_skip_len.take()
        };
        let mut next_skip_len = None;
        let mut first_byte_parse_failed = true;
        while !payload.is_empty() {
            let mut info = OpenWireInfo::default();
            match self.parse_one(&mut info, payload, param) {
                Ok(p) => {
                    payload = p;
                    infos.push(L7ProtocolInfo::OpenWireInfo(info));
                }
                Err(Error::OpenWireLogParseUnimplemented) => {
                    let msg_size = match info.get_msg_size() {
                        Some(msg_size) => 4 + msg_size as usize,
                        None => break,
                    };
                    infos.push(L7ProtocolInfo::OpenWireInfo(info));
                    if !self.is_size_prefix_disabled {
                        payload = match payload.get(msg_size..) {
                            Some(p) => p,
                            None => {
                                next_skip_len = Some(msg_size - payload.len());
                                break;
                            }
                        };
                    } else {
                        break;
                    }
                }
                Err(Error::OpenWireLogParseEOF) => {
                    let msg_size = match info.get_msg_size() {
                        Some(msg_size) => 4 + msg_size as usize,
                        None => break,
                    };
                    infos.push(L7ProtocolInfo::OpenWireInfo(info));
                    if !self.is_size_prefix_disabled {
                        next_skip_len = Some(msg_size - payload.len());
                    }
                    break;
                }
                Err(Error::OpenWireLogParseFailed) => {
                    if first_byte_parse_failed {
                        first_byte_parse_failed = false;
                        // parse failed at the start of the payload,
                        // try to skip the cached next_skip_len
                        if infos.is_empty() {
                            if let Some(skip_len) = current_skip_len.take() {
                                match payload.get(skip_len..) {
                                    Some(p) => {
                                        payload = p;
                                        continue;
                                    }
                                    // conservatively skip only one packet
                                    None => break,
                                };
                            }
                        }
                    }
                    payload = payload.get(1..).unwrap_or_default();
                }
                _ => break,
            }
        }
        if param.direction == PacketDirection::ClientToServer {
            self.client_next_skip_len = next_skip_len;
        } else {
            self.server_next_skip_len = next_skip_len;
        }
        infos
    }
    fn check_protocol(payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }
        // only parse the initial WIREFORMAT_INFO command to check the protocol
        let mut parser = Self::default();
        let mut info = OpenWireInfo::default();
        match parser.do_unmarshal(&mut info, payload, param) {
            Ok(_) => info.command_type == OpenWireCommand::WireFormatInfo,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::Path;
    use std::{fs, rc::Rc};

    use super::*;

    use crate::common::l7_protocol_log::L7PerfCache;
    use crate::config::handler::LogParserConfig;
    use crate::flow_generator::L7_RRT_CACHE_CAPACITY;
    use crate::{
        common::{flow::PacketDirection, MetaPacket},
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/openwire";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), Some(1500));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut openwire = OpenWireLog::default();
        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
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
            );
            let parse_config = &LogParserConfig {
                l7_log_dynamic: config.clone(),
                ..Default::default()
            };
            param.set_log_parse_config(parse_config);

            let is_openwire = OpenWireLog::check_protocol(payload, param);
            let infos = openwire.parse(payload, param);
            if infos.is_empty() {
                output.push_str("This packet payload cannot be parsed\n");
            } else {
                for info in infos {
                    match info {
                        L7ProtocolInfo::OpenWireInfo(info) => {
                            output.push_str(&format!("{:?} is_openwire: {}\n", info, is_openwire));
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("openwire_exception.pcap", "openwire_exception.result"),
            (
                "openwire_correlation_id.pcap",
                "openwire_correlation_id.result",
            ),
            (
                "openwire_tight_producer.pcap",
                "openwire_tight_producer.result",
            ),
            (
                "openwire_tight_consumer.pcap",
                "openwire_tight_consumer.result",
            ),
            (
                "openwire_loose_producer.pcap",
                "openwire_loose_producer.result",
            ),
            (
                "openwire_loose_consumer.pcap",
                "openwire_loose_consumer.result",
            ),
            ("openwire_injected.pcap", "openwire_injected.result"),
            ("openwire_segmented.pcap", "openwire_segmented.result"),
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
    fn check_parse_sw8_header() {
        let payload = b"\x00\x03sw8\x09\x00\x1E1-VFJBQ0VJRA==-U0VHTUVOVElE-3-";
        let config = L7LogDynamicConfig::new(
            "".to_owned(),
            vec![],
            vec![TraceType::Sw8, TraceType::TraceParent],
            vec![TraceType::Sw8, TraceType::TraceParent],
        );
        let (trace_id, span_id) = parse_trace_and_span(payload, &config).unwrap();
        assert_eq!(trace_id, Some("TRACEID".to_string()));
        assert_eq!(span_id, Some("SEGMENTID-3".to_string()));
    }
}
