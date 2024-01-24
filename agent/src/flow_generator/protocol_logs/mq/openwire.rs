use std::fmt;

use nom::{bytes, error, number, Err, IResult};
use serde::Serialize;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            decode_base64_to_string,
            pb_adapter::{L7ProtocolSendLog, L7Request, L7Response, TraceInfo},
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
1	WIREFORMAT_INFO
2	BROKER_INFO
3	CONNECTION_INFO
4	SESSION_INFO
5	CONSUMER_INFO
6	PRODUCER_INFO
7	TRANSACTION_INFO
8	DESTINATION_INFO
9	REMOVE_SUBSCRIPTION_INFO
10	KEEP_ALIVE_INFO
11	SHUTDOWN_INFO
12	REMOVE_INFO
14	CONTROL_COMMAND
15	FLUSH_COMMAND
16	CONNECTION_ERROR
17	CONSUMER_CONTROL
18	CONNECTION_CONTROL
21	MESSAGE_DISPATCH
22	MESSAGE_ACK
23	ACTIVEMQ_MESSAGE
24	ACTIVEMQ_BYTES_MESSAGE
25	ACTIVEMQ_MAP_MESSAGE
26	ACTIVEMQ_OBJECT_MESSAGE
27	ACTIVEMQ_STREAM_MESSAGE
28	ACTIVEMQ_TEXT_MESSAGE
30	RESPONSE
31	EXCEPTION_RESPONSE
32	DATA_RESPONSE
33	DATA_ARRAY_RESPONSE
34	INTEGER_RESPONSE
40	DISCOVERY_EVENT
50	JOURNAL_TOPIC_ACK (not in out-of-date OpenWire V2 Specification: "https://activemq.apache.org/openwire-version-2-specification")
52	JOURNAL_QUEUE_ACK (not in out-of-date OpenWire V2 Specification)
53	JOURNAL_TRACE
54	JOURNAL_TRANSACTION
55	DURABLE_SUBSCRIPTION_INFO
60	PARTIAL_COMMAND
61	PARTIAL_LAST_COMMAND
65	REPLAY
70	BYTE_TYPE
71	CHAR_TYPE
72	SHORT_TYPE
73	INTEGER_TYPE
74	LONG_TYPE
75	DOUBLE_TYPE
76	FLOAT_TYPE
77	STRING_TYPE
78	BOOLEAN_TYPE
79	BYTE_ARRAY_TYPE
90	MESSAGE_DISPATCH_NOTIFICATION
91	NETWORK_BRIDGE_FILTER
100	ACTIVEMQ_QUEUE
101	ACTIVEMQ_TOPIC
102	ACTIVEMQ_TEMP_QUEUE
103	ACTIVEMQ_TEMP_TOPIC
110	MESSAGE_ID
111	ACTIVEMQ_LOCAL_TRANSACTION_ID
112	ACTIVEMQ_XA_TRANSACTION_ID
120	CONNECTION_ID
121	SESSION_ID
122	CONSUMER_ID
123	PRODUCER_ID
124	BROKER_ID
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
                    _ => Err(Error::OpenwireLogParseFailed)
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
    MessageDispatch(MessageDispatch, 21),
    MessageAck(MessageAck, 22),
    ActiveMQMessage(ActiveMQMessage, 23),
    ActiveMQBytesMessage(ActiveMQBytesMessage, 24),
    ActiveMQMapMessage(ActiveMQMapMessage, 25),
    ActiveMQObjectMessage(ActiveMQObjectMessage, 26),
    ActiveMQStreamMessage(ActiveMQStreamMessage, 27),
    ActiveMQTextMessage(ActiveMQTextMessage, 28),
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
                    _ => Err(Error::OpenwireLogParseUnimplemented),
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
                    _ => Err(Error::OpenwireLogParseUnimplemented),
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
                    _ => BaseCommand::tight_unmarshal(parser, info, bs, payload),
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
                    _ => BaseCommand::loose_unmarshal(parser, info, payload),
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
    ActiveMQLocalTransactionId,
    ActiveMQXATransactionId,
    ConnectionId,
    SessionId,
    ConsumerId,
    ProducerId,
    // topic and queue
    ActiveMQTopic,
    ActiveMQQueue,
    ActiveMQTempTopic,
    ActiveMQTempQueue,
    ActiveMQMessage,
    // message types
    ActiveMQBytesMessage,
    ActiveMQMapMessage,
    ActiveMQObjectMessage,
    ActiveMQStreamMessage,
    ActiveMQTextMessage,
    // message dispatch and ack
    MessageDispatch,
    MessageAck,
);

struct BooleanStream<'a> {
    payload: &'a [u8],
    offset: usize,
    bitpos: usize,
}

impl<'a> BooleanStream<'a> {
    fn new(payload: &'a [u8]) -> Self {
        BooleanStream {
            payload,
            offset: 0,
            bitpos: 0,
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
    fn read_boolean_stream(payload: &'a [u8]) -> IResult<&'a [u8], Self> {
        // read bollean stream length
        let (mut payload, byte) = number::complete::be_u8(payload)?;
        let mut bs_length = byte as usize;
        match bs_length {
            0xC0 => {
                let (new_payload, byte) = number::complete::be_u8(payload)?;
                bs_length = byte as usize;
                payload = new_payload;
            }
            0x80 => {
                let (new_payload, short) = number::complete::be_u16(payload)?;
                bs_length = short as usize;
                payload = new_payload;
            }
            _ => {}
        }
        // read boolean stream
        let (payload, bs) = bytes::complete::take(bs_length)(payload)?;
        Ok((payload, Self::new(bs)))
    }
}

fn parse_byte<'a>(payload: &'a [u8]) -> Result<(&'a [u8], u8)> {
    let (payload, byte) = number::complete::be_u8(payload)
        .map_err(|_: Err<error::Error<_>>| Error::OpenwireLogParseFailed)?;
    Ok((payload, byte))
}
fn parse_short<'a>(payload: &'a [u8]) -> Result<(&'a [u8], u16)> {
    let (payload, short) = number::complete::be_u16(payload)
        .map_err(|_: Err<error::Error<_>>| Error::OpenwireLogParseFailed)?;
    Ok((payload, short))
}
fn parse_integer<'a>(payload: &'a [u8]) -> Result<(&'a [u8], u32)> {
    let (payload, integer) = number::complete::be_u32(payload)
        .map_err(|_: Err<error::Error<_>>| Error::OpenwireLogParseFailed)?;
    Ok((payload, integer))
}
fn parse_long<'a>(payload: &'a [u8]) -> Result<(&'a [u8], u64)> {
    let (payload, long) = number::complete::be_u64(payload)
        .map_err(|_: Err<error::Error<_>>| Error::OpenwireLogParseFailed)?;
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
        .map_err(|_: Err<error::Error<_>>| Error::OpenwireLogParseFailed)?;
    Ok((payload, bytes))
}
fn parse_command_type(payload: &[u8]) -> Result<(&[u8], OpenWireCommand)> {
    let (payload, command_type) = bytes::complete::take(1usize)(payload)
        .map_err(|_: Err<error::Error<_>>| Error::OpenwireLogParseFailed)?;
    let command_type = OpenWireCommand::try_from(command_type[0])?;
    Ok((payload, command_type))
}
fn parse_sw8_trace_id(payload: &[u8]) -> Result<String> {
    // header pattern: "sw8\x09<length in short type>1-<trace id>-"
    let header_pattern = b"sw8\x09";
    let mut next_payload = payload;
    while next_payload.len() > header_pattern.len() {
        let payload = next_payload;
        next_payload = next_payload.get(1..).unwrap_or_default();
        // match "sw8\x09"
        let payload = match payload
            .windows(header_pattern.len())
            .position(|window| window == header_pattern)
        {
            Some(index) => &payload[index + header_pattern.len()..],
            None => continue,
        };
        // parse length
        let payload = match parse_short(payload) {
            Ok((payload, _)) => payload,
            Err(_) => continue,
        };
        // match "1-"
        if payload.get(0..2) != Some(b"1-") {
            continue;
        }
        let payload = &payload[2..];
        // find next "-"
        let trace_id = match payload.iter().position(|&c| c == b'-') {
            Some(index) => &payload[..index],
            None => continue,
        };
        // parse trace_id
        let trace_id = match std::str::from_utf8(&trace_id) {
            Ok(trace_id) => trace_id,
            Err(_) => continue,
        };
        // base64 decode
        let trace_id = decode_base64_to_string(trace_id);
        return Ok(trace_id);
    }
    Err(Error::OpenwireLogParseFailed)
}

enum DataType<'a> {
    Byte(u8),
    Char(u8),
    Short(u16),
    Integer(u32),
    Long(u64),
    Double(f64),
    Float(f32),
    String(&'a str),
    Boolean(bool),
    ByteArray(&'a [u8]),
}
trait Unmarshal {
    #[allow(unused_variables)]
    fn tight_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        bs: &mut BooleanStream,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        Err(Error::OpenwireLogParseFailed)
    }
    #[allow(unused_variables)]
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        Err(Error::OpenwireLogParseFailed)
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
        info.command_id = command_id;
        // parse responseRequired
        match bs.read_bool() {
            Some(_) => Ok(payload),
            None => Err(Error::OpenwireLogParseFailed),
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
        // parse responseRequired
        let (payload, _) = parse_boolean(payload)?;
        Ok(payload)
    }
}

impl BaseDataStream {
    fn tight_unmarshal_string<'a>(
        payload: &'a [u8],
        bs: &mut BooleanStream,
    ) -> Result<(&'a [u8], Option<DataType<'a>>)> {
        match bs.read_bool() {
            Some(true) => match bs.read_bool() {
                Some(_) => {
                    let (payload, length) = parse_short(payload)?;
                    let (payload, string) = parse_bytes(payload, length as usize)?;
                    Ok((
                        payload,
                        Some(DataType::String(
                            std::str::from_utf8(string)
                                .map_err(|_| Error::OpenwireLogParseFailed)?,
                        )),
                    ))
                }
                None => Err(Error::OpenwireLogParseFailed),
            },
            Some(false) => Ok((payload, None)),
            None => Err(Error::OpenwireLogParseFailed),
        }
    }
    fn loose_unmarshal_string<'a>(payload: &'a [u8]) -> Result<(&'a [u8], Option<DataType>)> {
        match parse_boolean(payload) {
            Ok((payload, true)) => {
                let (payload, length) = parse_short(payload)?;
                let (payload, string) = parse_bytes(payload, length as usize)?;
                Ok((
                    payload,
                    Some(DataType::String(
                        std::str::from_utf8(string).map_err(|_| Error::OpenwireLogParseFailed)?,
                    )),
                ))
            }
            Ok((payload, false)) => Ok((payload, None)),
            Err(_) => Err(Error::OpenwireLogParseFailed),
        }
    }
    fn tight_unmarshal_long<'a>(
        payload: &'a [u8],
        bs: &mut BooleanStream,
    ) -> Result<(&'a [u8], Option<DataType<'a>>)> {
        if bs.read_bool().ok_or(Error::OpenwireLogParseFailed)? {
            if bs.read_bool().ok_or(Error::OpenwireLogParseFailed)? {
                let (payload, long) = parse_long(payload)?;
                Ok((payload, Some(DataType::Long(long))))
            } else {
                let (payload, integer) = parse_integer(payload)?;
                Ok((payload, Some(DataType::Long(integer as u64))))
            }
        } else {
            if bs.read_bool().ok_or(Error::OpenwireLogParseFailed)? {
                let (payload, long) = parse_short(payload)?;
                Ok((payload, Some(DataType::Long(long as u64))))
            } else {
                Ok((payload, Some(DataType::Long(0))))
            }
        }
    }
    fn tight_unmarshal_byte_array<'a>(
        payload: &'a [u8],
        bs: &mut BooleanStream,
    ) -> Result<(&'a [u8], Option<DataType<'a>>)> {
        match bs.read_bool() {
            Some(true) => {
                let (payload, length) = parse_integer(payload)?;
                let (payload, bytes) = parse_bytes(payload, length as usize)?;
                Ok((payload, Some(DataType::ByteArray(bytes))))
            }
            Some(false) => Ok((payload, None)),
            None => Err(Error::OpenwireLogParseFailed),
        }
    }
    fn loose_unmarshal_byte_array<'a>(
        payload: &'a [u8],
    ) -> Result<(&'a [u8], Option<DataType<'a>>)> {
        match parse_boolean(payload)? {
            (payload, true) => {
                let (payload, length) = parse_integer(payload)?;
                let (payload, bytes) = parse_bytes(payload, length as usize)?;
                Ok((payload, Some(DataType::ByteArray(bytes))))
            }
            (payload, false) => Ok((payload, None)),
        }
    }
    fn loose_unmarshal_long<'a>(payload: &'a [u8]) -> Result<(&'a [u8], Option<DataType>)> {
        let (payload, long) = parse_long(payload)?;
        Ok((payload, Some(DataType::Long(long))))
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
                    let _ = bs.read_bool().ok_or(Error::OpenwireLogParseFailed)?;
                }
                let data_marshaller = OpenWireCommandMarshaller::from(data_type);
                data_marshaller.tight_unmarshal(parser, info, bs, payload)
            }
            Some(false) => Ok(payload),
            None => Err(Error::OpenwireLogParseFailed),
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
        if parser.is_cache_enabled.unwrap_or(CACHE_ENABLED_DEFAULT) {
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
                None => Err(Error::OpenwireLogParseFailed),
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
        if parser.is_cache_enabled.unwrap_or(CACHE_ENABLED_DEFAULT) {
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
    fn is_marshall_aware(command_type: OpenWireCommand) -> bool {
        match command_type {
            // WireFormatInfo and ActiveMQMessage
            OpenWireCommand::WireFormatInfo
            | OpenWireCommand::ActiveMQMessage
            | OpenWireCommand::ActiveMQBytesMessage
            | OpenWireCommand::ActiveMQMapMessage
            | OpenWireCommand::ActiveMQObjectMessage
            | OpenWireCommand::ActiveMQStreamMessage
            | OpenWireCommand::ActiveMQTextMessage => true,
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
        BaseDataStream::tight_unmarshal_nested_object(parser, info, bs, payload)
    }
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse transactionId
        let (payload, _) = BaseDataStream::loose_unmarshal_long(payload)?;
        // parse connetionId
        BaseDataStream::loose_unmarshal_nested_object(parser, info, payload)
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
        match connection_id {
            Some(DataType::String(connection_id)) => {
                info.connection_id = Some(connection_id.to_string());
                Ok(payload)
            }
            _ => Err(Error::OpenwireLogParseFailed),
        }
    }
    fn loose_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        let (payload, connection_id) = BaseDataStream::loose_unmarshal_string(payload)?;
        match connection_id {
            Some(DataType::String(connection_id)) => {
                info.connection_id = Some(connection_id.to_string());
                Ok(payload)
            }
            _ => Err(Error::OpenwireLogParseFailed),
        }
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
        match connection_id {
            Some(DataType::String(connection_id)) => {
                info.connection_id = Some(connection_id.to_string());
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }
        // parse sessionId
        let (payload, session_id) = BaseDataStream::tight_unmarshal_long(payload, bs)?;
        match session_id {
            Some(DataType::Long(session_id)) => {
                info.session_id = Some(session_id);
                Ok(payload)
            }
            _ => Err(Error::OpenwireLogParseFailed),
        }
    }
    fn loose_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse connectionId
        let (payload, connection_id) = BaseDataStream::loose_unmarshal_string(payload)?;
        match connection_id {
            Some(DataType::String(connection_id)) => {
                info.connection_id = Some(connection_id.to_string());
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }
        // parse sessionId
        let (payload, session_id) = BaseDataStream::loose_unmarshal_long(payload)?;
        match session_id {
            Some(DataType::Long(session_id)) => {
                info.session_id = Some(session_id);
                Ok(payload)
            }
            _ => Err(Error::OpenwireLogParseFailed),
        }
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
        match connection_id {
            Some(DataType::String(connection_id)) => {
                info.connection_id = Some(connection_id.to_string());
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }
        // parse sessionId
        let (payload, session_id) = BaseDataStream::tight_unmarshal_long(payload, bs)?;
        match session_id {
            Some(DataType::Long(session_id)) => {
                info.session_id = Some(session_id);
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }
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
        match connection_id {
            Some(DataType::String(connection_id)) => {
                info.connection_id = Some(connection_id.to_string());
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }
        // parse sessionId
        let (payload, session_id) = BaseDataStream::loose_unmarshal_long(payload)?;
        match session_id {
            Some(DataType::Long(session_id)) => {
                info.session_id = Some(session_id);
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }
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
        match connection_id {
            Some(DataType::String(connection_id)) => {
                info.connection_id = Some(connection_id.to_string());
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }
        // parse producerId
        let (payload, _) = BaseDataStream::tight_unmarshal_long(payload, bs)?;
        // parse sessionId
        let (payload, session_id) = BaseDataStream::tight_unmarshal_long(payload, bs)?;
        match session_id {
            Some(DataType::Long(session_id)) => {
                info.session_id = Some(session_id);
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }
        Ok(payload)
    }
    fn loose_unmarshal<'a>(
        _parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse connectionId
        let (payload, connection_id) = BaseDataStream::loose_unmarshal_string(payload)?;
        match connection_id {
            Some(DataType::String(connection_id)) => {
                info.connection_id = Some(connection_id.to_string());
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }
        // parse producerId
        let (payload, _) = BaseDataStream::loose_unmarshal_long(payload)?;
        // parse sessionId
        let (payload, session_id) = BaseDataStream::loose_unmarshal_long(payload)?;
        match session_id {
            Some(DataType::Long(session_id)) => {
                info.session_id = Some(session_id);
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }
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
        let (_, client_id) = BaseDataStream::tight_unmarshal_string(payload, bs)?;
        match client_id {
            Some(DataType::String(client_id)) => {
                info.client_id = Some(client_id.to_string());
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }
        // TODO: more fields are not supported
        Err(Error::OpenwireLogParseUnimplemented)
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
        let (_, client_id) = BaseDataStream::loose_unmarshal_string(payload)?;
        match client_id {
            Some(DataType::String(client_id)) => {
                info.client_id = Some(client_id.to_string());
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }
        // TODO: more fields are not supported
        Err(Error::OpenwireLogParseUnimplemented)
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
        let _ = bs.read_bool().ok_or(Error::OpenwireLogParseFailed)?;
        // parse destination
        let _ = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        // TODO: more fields are not supported
        Err(Error::OpenwireLogParseUnimplemented)
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
        Err(Error::OpenwireLogParseUnimplemented)
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
        Err(Error::OpenwireLogParseUnimplemented)
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
        Err(Error::OpenwireLogParseUnimplemented)
    }
}

impl Unmarshal for WireFormatInfo {
    // we do not implement tight_unmarshal for WireFormatInfo
    // since it is the first message in the log and the
    // tight_encoding flag is not negotiated yet
    fn loose_unmarshal<'a>(
        parser: &mut OpenWireLog,
        info: &mut OpenWireInfo,
        payload: &'a [u8],
    ) -> Result<&'a [u8]> {
        // parse magic field "ActiveMQ"
        let (payload, magic) = parse_bytes(payload, 8usize)?;
        match std::str::from_utf8(magic) {
            Ok(magic) => {
                if magic != "ActiveMQ" {
                    return Err(Error::OpenwireLogParseFailed);
                }
            }
            _ => {
                return Err(Error::OpenwireLogParseFailed);
            }
        }

        // parse version
        let (payload, version) = parse_integer(payload)?;
        parser.version = version;
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
        for (idx, left) in payload.windows(key.len()).enumerate() {
            if left == key {
                match payload.get(idx + key.len()) {
                    Some(value) => {
                        let boolean = value != &0;
                        info.is_tight_encoding = Some(boolean);
                        parser.is_tight_encoding =
                            Some(parser.is_tight_encoding.unwrap_or(true) && boolean);
                    }
                    _ => return Err(Error::OpenwireLogParseFailed),
                }
                break;
            }
        }

        // parse SizePrefixDisabled
        let key = "SizePrefixDisabled\x01".as_bytes();
        for (idx, left) in payload.windows(key.len()).enumerate() {
            if left == key {
                match payload.get(idx + key.len()) {
                    Some(value) => {
                        let boolean = value != &0;
                        info.is_size_prefix_disabled = Some(boolean);
                        parser.is_size_prefix_disabled =
                            Some(parser.is_size_prefix_disabled.unwrap_or(true) && boolean);
                    }
                    _ => return Err(Error::OpenwireLogParseFailed),
                }
                break;
            }
        }

        // parse CacheEnabled
        let key = "CacheEnabled\x01".as_bytes();
        for (idx, left) in payload.windows(key.len()).enumerate() {
            if left == key {
                match payload.get(idx + key.len()) {
                    Some(value) => {
                        let boolean = value != &0;
                        info.is_cache_enabled = Some(boolean);
                        parser.is_cache_enabled =
                            Some(parser.is_cache_enabled.unwrap_or(true) && boolean);
                    }
                    _ => return Err(Error::OpenwireLogParseFailed),
                }
                break;
            }
        }
        // take the rest of payload
        let (payload, _) = parse_bytes(payload, length as usize)?;
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
        let _ = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
        Err(Error::OpenwireLogParseUnimplemented)
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
        let _ = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
        Err(Error::OpenwireLogParseUnimplemented)
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
                // parse destination
                let _ = BaseDataStream::tight_unmarshal_cached_object(parser, info, bs, payload)?;
                Err(Error::OpenwireLogParseUnimplemented)
            }
            fn loose_unmarshal<'a>(
                parser: &mut OpenWireLog,
                info: &mut OpenWireInfo,
                payload: &'a [u8],
            ) -> Result<&'a [u8]> {
                // parse commandId and responseRequired
                let payload = BaseCommand::loose_unmarshal(parser, info, payload)?;
                // parse destination
                let _ = BaseDataStream::loose_unmarshal_cached_object(parser, info, payload)?;
                Err(Error::OpenwireLogParseUnimplemented)
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
    ActiveMQTextMessage
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
                match topic {
                    Some(DataType::String(topic)) => {
                        info.topic = Some(topic.to_string());
                        Ok(paydload)
                    }
                    _ => Err(Error::OpenwireLogParseFailed),
                }
            }
            fn loose_unmarshal<'a>(
                _parser: &mut OpenWireLog,
                info: &mut OpenWireInfo,
                payload: &'a [u8],
            ) -> Result<&'a [u8]> {
                // parse topic string
                let (paydload, topic) = BaseDataStream::loose_unmarshal_string(payload)?;
                match topic {
                    Some(DataType::String(topic)) => {
                        info.topic = Some(topic.to_string());
                        Ok(paydload)
                    }
                    _ => Err(Error::OpenwireLogParseFailed),
                }
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
    is_tight_encoding: Option<bool>,
    #[serde(skip)]
    is_size_prefix_disabled: Option<bool>,
    #[serde(skip)]
    is_cache_enabled: Option<bool>,

    #[serde(skip_serializing_if = "value_is_default")]
    pub version: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,

    pub command_type: OpenWireCommand,
    pub command_id: u32,

    #[serde(rename = "request_length", skip_serializing_if = "value_is_negative")]
    pub req_msg_size: Option<u32>,
    #[serde(rename = "response_length", skip_serializing_if = "value_is_negative")]
    pub res_msg_size: Option<u32>,

    pub status: L7ResponseStatus,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,

    rtt: u64,
}

impl Default for OpenWireInfo {
    fn default() -> Self {
        OpenWireInfo {
            msg_type: Default::default(),
            is_tls: false,
            is_tight_encoding: None,
            is_size_prefix_disabled: None,
            is_cache_enabled: None,
            version: 0,
            connection_id: None,
            client_id: None,
            session_id: None,
            topic: None,
            command_type: OpenWireCommand::WireFormatInfo,
            command_id: 0,
            req_msg_size: None,
            res_msg_size: None,
            status: L7ResponseStatus::Ok,
            trace_id: None,
            rtt: 0,
        }
    }
}

impl OpenWireInfo {
    fn merge(&mut self, other: &Self) {
        if self.res_msg_size.is_none() {
            self.res_msg_size = other.res_msg_size;
        }
        if self.req_msg_size.is_none() {
            self.req_msg_size = other.req_msg_size;
        }
        if self.connection_id.is_none() {
            self.connection_id = other.connection_id.clone();
        }
        if self.client_id.is_none() {
            self.client_id = other.client_id.clone();
        }
        if self.session_id.is_none() {
            self.session_id = other.session_id;
        }
        if self.topic.is_none() {
            self.topic = other.topic.clone();
        }
        if self.status == L7ResponseStatus::Ok {
            self.status = other.status;
        }
        if self.trace_id.is_none() {
            self.trace_id = other.trace_id.clone();
        }
    }
}

impl L7ProtocolInfoInterface for OpenWireInfo {
    fn session_id(&self) -> Option<u32> {
        self.session_id.map(|id| id as u32)
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
                domain: f.client_id.unwrap_or_default(),
                resource: f.topic.unwrap_or_default(),
                endpoint: f.connection_id.unwrap_or_default(),
            },
            resp: L7Response {
                status: f.status,
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: f.trace_id,
                ..Default::default()
            }),
            version: Some(f.version.to_string()),
            flags,
            ..Default::default()
        }
    }
}

const TIGHT_ENCODING_DEFAULT: bool = true;
const SIZE_PREFIX_DISABLED_DEFAULT: bool = false;
const CACHE_ENABLED_DEFAULT: bool = true;
#[derive(Default)]
pub struct OpenWireLog {
    msg_type: LogMessageType,
    status: L7ResponseStatus,
    is_tight_encoding: Option<bool>,
    is_size_prefix_disabled: Option<bool>,
    is_cache_enabled: Option<bool>,
    version: u32,

    perf_stats: Option<L7PerfStats>,
}

impl L7ProtocolParserInterface for OpenWireLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        Self::check_protocol(payload, param)
    }
    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let mut info = self.parse(payload, param)?;

        info.cal_rrt(param, None).map(|rtt| {
            info.rtt = rtt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rtt));
        });

        match param.direction {
            PacketDirection::ClientToServer => {
                self.perf_stats.as_mut().map(|p| p.inc_req());
            }
            PacketDirection::ServerToClient => {
                self.perf_stats.as_mut().map(|p| p.inc_resp());
            }
        }

        if param.parse_log {
            Ok(L7ParseResult::Single(info.into()))
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
    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl OpenWireLog {
    fn do_unmarshal(&mut self, mut payload: &[u8]) -> Result<OpenWireInfo> {
        let mut info = OpenWireInfo::default();
        let mut msg_size = payload.len();
        if !self
            .is_size_prefix_disabled
            .unwrap_or(SIZE_PREFIX_DISABLED_DEFAULT)
        {
            let (updated_payload, length) = parse_integer(payload)?;
            msg_size = length as usize;
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
            | OpenWireCommand::DiscoveryEvent
            | OpenWireCommand::DurableSubscriptionInfo
            | OpenWireCommand::PartialCommand
            | OpenWireCommand::PartialLastCommand
            | OpenWireCommand::Replay
            | OpenWireCommand::MessageDispatchNotification => {
                info.msg_type = LogMessageType::Session;
                info.res_msg_size = Some(msg_size as u32);
            }
            OpenWireCommand::MessageDispatch
            | OpenWireCommand::ActiveMQMessage
            | OpenWireCommand::ActiveMQBytesMessage
            | OpenWireCommand::ActiveMQMapMessage
            | OpenWireCommand::ActiveMQObjectMessage
            | OpenWireCommand::ActiveMQStreamMessage
            | OpenWireCommand::ActiveMQTextMessage => {
                info.msg_type = LogMessageType::Request;
                info.req_msg_size = Some(msg_size as u32);
                // for request we try to parse sw8 trace_id
                info.trace_id = parse_sw8_trace_id(payload).ok();
            }
            OpenWireCommand::MessageAck
            | OpenWireCommand::Response
            | OpenWireCommand::ExceptionResponse
            | OpenWireCommand::DataResponse
            | OpenWireCommand::DataArrayResponse
            | OpenWireCommand::IntegerResponse => {
                info.msg_type = LogMessageType::Response;
                info.res_msg_size = Some(msg_size as u32);
            }
            _ => {
                info.msg_type = LogMessageType::Other;
                info.res_msg_size = Some(msg_size as u32);
            }
        };

        if command_type == OpenWireCommand::ConnectionError {
            info.status = L7ResponseStatus::ServerError;
        }

        if self.is_tight_encoding.unwrap_or(TIGHT_ENCODING_DEFAULT)
            && command_type != OpenWireCommand::WireFormatInfo
        {
            let (payload, mut bs) = BooleanStream::read_boolean_stream(payload)
                .map_err(|_: Err<error::Error<_>>| Error::OpenwireLogParseFailed)?;
            let data_marshaller = OpenWireCommandMarshaller::from(command_type);
            let res = data_marshaller.tight_unmarshal_command(self, &mut info, &mut bs, payload);
            // omit OpenwireLogParseUnimplemented error
            match res {
                Ok(_) | Err(Error::OpenwireLogParseUnimplemented) => Ok(info),
                Err(_) => Err(Error::OpenwireLogParseFailed),
            }
        } else {
            let res = OpenWireCommandMarshaller::from(command_type)
                .loose_unmarshal_command(self, &mut info, payload);
            // omit OpenwireLogParseUnimplemented error
            match res {
                Ok(_) | Err(Error::OpenwireLogParseUnimplemented) => Ok(info),
                Err(_) => Err(Error::OpenwireLogParseFailed),
            }
        }
    }
    fn parse(&mut self, payload: &[u8], param: &ParseParam) -> Result<OpenWireInfo> {
        let mut info = self.do_unmarshal(payload)?;
        info.is_tls = param.is_tls();
        Ok(info)
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
        match parser.do_unmarshal(payload) {
            Ok(res) => res.command_type == OpenWireCommand::WireFormatInfo,
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
    use crate::flow_generator::L7_RRT_CACHE_CAPACITY;
    use crate::{
        common::{flow::PacketDirection, MetaPacket},
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/openwire";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), Some(1024));
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
            let param = &ParseParam::new(
                packet as &MetaPacket,
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );

            let is_openwire = OpenWireLog::check_protocol(payload, param);
            match openwire.parse(payload, param) {
                Ok(info) => {
                    output.push_str(&format!("{:?} is_openwire: {}\r\n", info, is_openwire));
                }
                Err(_) => unreachable!(),
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
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
        let payload = b"\x00\x03sw8\x09\x01\x291-dGVzdA==-";
        let trace_id = parse_sw8_trace_id(payload).unwrap();
        assert_eq!(trace_id, "test");
    }
}
