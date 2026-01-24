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

use std::fmt::Display;
use std::io::{Cursor, Seek, SeekFrom};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{NaiveDate, NaiveDateTime, NaiveTime};

#[allow(dead_code)]
#[derive(Debug)]
pub struct TdsHeader {
    packet_type: u8,
    status: u8,
    length: u16,
    spid: u16,
    packet_id: u8,
    window: u8,
}

impl TdsHeader {
    const SIZE: usize = 8;

    fn is_invalid(&self) -> bool {
        (self.packet_type != 1 && self.packet_type != 4)
            || self.window != 0
            || self.length < Self::SIZE as u16
    }
}

#[derive(Debug, Clone)]
pub enum TdsToken {
    ColMetadata(Vec<ColumnMetadata>),
    Row(Vec<RowValue>),
    AltRow(Vec<RowValue>),         // 替代行格式
    NBCRow(Vec<Option<RowValue>>), // 稀疏行格式
    TabName(String),
    ColInfo(Vec<ColumnInfo>),
    Order(Vec<OrderColumn>),
    Done(DoneStatus),
    DoneProc(DoneStatus),
    DoneInProc(DoneStatus),
    ReturnStatus(i32),
    ReturnParam(Vec<ReturnParam>),
    EnvChange(EnvChange),
    Info(InfoMessage),
    Error(ErrorInfo),
    LoginAck(LoginAck),
    FeatureExtAck(FeatureExtAck),
    FedAuthInfo(FedAuthInfo),
    SessionState(SessionState),
    Sspi(Vec<u8>),
    RowFormat(u8), // 0x20: NBCRow, 0xD2: AltRow
    Unknown(u8),
}

#[derive(Debug, Clone)]
pub struct ColumnMetadata {
    pub user_type: u32,
    pub flags: u16,
    pub col_type: TdsDataType,
    pub col_len: u16,
    pub col_name: String,
    pub collation: Option<Collation>,
    pub table_name: Option<String>,
    pub schema_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ColumnInfo {
    pub col_num: u16,
    pub table_num: u16,
}

#[derive(Debug, Clone)]
pub struct OrderColumn {
    pub col_num: u16,
}

#[derive(Debug, Clone)]
pub struct ReturnParam {
    pub param_name: String,
    pub param_type: TdsDataType,
    pub param_len: u16,
    pub param_value: RowValue,
}

#[derive(Debug, Clone)]
pub struct DoneStatus {
    pub status: u16,
    pub cur_cmd: u16,
    pub row_count: u64,
}

#[allow(dead_code)]
impl DoneStatus {
    const STATUS_FLAGS_MORE_TOKEN: u16 = 0x1;
    const STATUS_FLAGS_ERR: u16 = 0x2;
    const STATUS_FLAGS_IN_TRANSACTION: u16 = 0x4;
    const STATUS_FLAGS_ROW_COUNT_VALID: u16 = 0x10;

    fn is_valid_row_count(&self) -> bool {
        self.status & Self::STATUS_FLAGS_ROW_COUNT_VALID != 0
    }
}

#[derive(Debug, Clone)]
pub struct LoginAck {
    pub interface: u8,
    pub tds_version: u32,
    pub prog_name: String,
    pub prog_version: u32,
}

#[derive(Debug, Clone)]
pub struct Feature {
    pub id: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FeatureExtAck {
    pub features: Vec<Feature>,
}

#[derive(Debug, Clone)]
pub struct FedAuthInfo {
    pub sts_url: String,
    pub spn: String,
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub state: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct InfoMessage {
    pub number: i32,
    pub state: u8,
    pub class: u8,
    pub message: String,
    pub server_name: String,
    pub proc_name: String,
    pub line_number: u32,
}

#[derive(Debug, Clone)]
pub struct ErrorInfo {
    pub number: i32,
    pub state: u8,
    pub class: u8,
    pub message: String,
    pub server_name: String,
    pub proc_name: String,
    pub line_number: u32,
}

#[derive(Debug, Clone)]
pub enum EnvChange {
    Database(String),
    Language(String),
    CharacterSet(String),
    PacketSize(u32),
    UnicodeSorting(bool),
    UnicodeSortingLocale(u16),
    SqlCollation(Collation),
    BeginTransaction,
    CommitTransaction,
    RollbackTransaction,
    EnlistDTCTransaction,
    DefectTransaction,
    DatabaseMirroringPartner(String),
    PromoteTransaction,
    TransactionManagerAddress(String),
    TransactionEnded,
    ResetConnection,
    UserInstance,
    Routing(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Collation {
    pub lcid: u32,
    pub flags: u16,
    pub version: u8,
    pub sort_id: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TdsDataType {
    Null,
    TinyInt,
    SmallInt,
    Int,
    BigInt,
    Float4,
    Float8,
    Money,
    Money4,
    DateTime,
    DateTime4,
    Decimal,
    Numeric,
    Bit,
    Guid,
    Intn,
    Decimaln,
    Numericn,
    Floatn,
    Moneyn,
    Datetimen,
    Char,
    Varchar,
    Binary,
    Varbinary,
    NChar,
    NVarchar,
    Text,
    NText,
    Image,
    VarLenType(u8), // 长度可变类型
}

#[derive(Debug, Clone)]
pub enum RowValue {
    Null,
    TinyInt(u8),
    SmallInt(i16),
    Int(i32),
    BigInt(i64),
    Float4(f32),
    Float8(f64),
    Money(i64),  // 以 1/10000 为单位
    Money4(i32), // 以 1/10000 为单位
    DateTime(NaiveDateTime),
    DateTime4(NaiveDate),
    Decimal(Vec<u8>, u8), // 数据，小数位数
    Numeric(Vec<u8>, u8), // 数据，小数位数
    Bit(bool),
    Guid(u128),
    String(String),
    Binary(Vec<u8>),
    UnicodeString(String),
    Unknown(u8, Vec<u8>),
}

// 参数状态
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ParamStatus {
    pub by_reference: bool,
    pub default_value: bool,
}

impl From<u8> for ParamStatus {
    fn from(value: u8) -> Self {
        ParamStatus {
            by_reference: (value & 0x01) != 0,
            default_value: (value & 0x02) != 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DataType {
    Null,
    TinyInt,
    Bit,
    SmallInt,
    Int,
    Smalldatetime,
    Real,
    Money,
    Datetime,
    Float,
    Decimal,
    Numeric,
    Smallmoney,
    BigInt,
    VarBinary,
    VarChar,
    Binary,
    Char,
    NVarChar,
    NChar,
    Xml,
    Udt,
    Other(u8),
}

impl From<u8> for DataType {
    fn from(value: u8) -> Self {
        match value {
            0x1F => DataType::Null,
            0x30 => DataType::TinyInt,
            0x32 => DataType::Bit,
            0x34 => DataType::SmallInt,
            0x38 => DataType::Int,
            0x3A => DataType::Smalldatetime,
            0x3B => DataType::Real,
            0x3C => DataType::Money,
            0x3D => DataType::Datetime,
            0x3E => DataType::Float,
            0x37 => DataType::Decimal,
            0x3F => DataType::Numeric,
            0x7A => DataType::Smallmoney,
            0x7F => DataType::BigInt,
            0xA5 => DataType::VarBinary,
            0xA7 => DataType::VarChar,
            0xAD => DataType::Binary,
            0xAF => DataType::Char,
            0xE7 => DataType::NVarChar,
            0xEF => DataType::NChar,
            0xF1 => DataType::Xml,
            0xF0 => DataType::Udt,
            v => DataType::Other(v),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParameterValue {
    Null,
    TinyInt(u8),
    Bit(bool),
    SmallInt(i16),
    Int(i32),
    BigInt(i64),
    Real(f32),
    Float(f64),
    String(String),
    Binary(Vec<u8>),
    Other(Vec<u8>),
}

impl Display for ParameterValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            ParameterValue::Null => write!(f, "Null"),
            ParameterValue::TinyInt(x) => write!(f, "TinyInt({})", x),
            ParameterValue::Bit(x) => write!(f, "Bit({})", x),
            ParameterValue::SmallInt(x) => write!(f, "SmallInt({})", x),
            ParameterValue::Int(x) => write!(f, "Int({})", x),
            ParameterValue::BigInt(x) => write!(f, "BigInt({})", x),
            ParameterValue::Real(x) => write!(f, "Real({})", x),
            ParameterValue::Float(x) => write!(f, "Float({})", x),
            ParameterValue::String(x) => write!(f, "String({})", x),
            ParameterValue::Binary(x) => write!(f, "Binary({:?})", x),
            ParameterValue::Other(x) => write!(f, "Other({:?})", x),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpcParameter {
    pub name: String,
    pub status: ParamStatus,
    pub data_type: DataType,
    pub max_length: u16,
    pub precision: u8,
    pub scale: u8,
    pub value: ParameterValue,
}

impl Display for RpcParameter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

pub struct TdsParser {
    cursor: Cursor<Bytes>,

    pub sql: Option<String>,
    pub status_code: Option<i32>,
    pub error_message: Option<String>,
    pub affected_row: Option<u64>,
}

impl TdsParser {
    pub fn new(data: &[u8]) -> Self {
        let mut packet = BytesMut::with_capacity(data.len());

        packet.put_slice(data);

        Self {
            cursor: Cursor::new(packet.freeze()),
            status_code: None,
            affected_row: None,
            error_message: None,
            sql: None,
        }
    }

    fn parse_header(&mut self) -> Result<TdsHeader, ParserError> {
        if TdsHeader::SIZE > self.cursor.remaining() {
            return Err(ParserError::InsufficientData);
        }

        let packet_type = self.cursor.get_u8();
        let status = self.cursor.get_u8();
        let length = self.cursor.get_u16();
        let spid = self.cursor.get_u16();
        let packet_id = self.cursor.get_u8();
        let window = self.cursor.get_u8();

        let header = TdsHeader {
            packet_type,
            status,
            length,
            spid,
            packet_id,
            window,
        };

        if header.is_invalid() {
            return Err(ParserError::InvalidData);
        }

        Ok(header)
    }

    fn parse_token(&mut self) -> Result<TdsToken, ParserError> {
        let token_type = self.cursor.get_u8();

        match token_type {
            // COL METADATA (0x81)
            0x81 => self.parse_colmetadata(),

            // ROW (0xD1)
            0xD1 => self.parse_row(),

            // ALTMETADATA (0x88)
            //0x88 => self.parse_altmetadata(),

            // ALTROW (0xD3)
            0xD3 => self.parse_altrow(),

            // NBCROW (0xD2)
            0xD2 => self.parse_nbcrow(),

            // TABNAME (0xA4)
            0xA4 => self.parse_tabname(),

            // COLINFO (0xA5)
            0xA5 => self.parse_colinfo(),

            // ORDER (0xA9)
            0xA9 => self.parse_order(),

            // DONE (0xFD, 0xFE, 0xFF)
            0xFD => self.parse_done(),
            0xFE => self.parse_doneproc(),
            0xFF => self.parse_doneinproc(),

            // RETURNSTATUS (0x79)
            0x79 => self.parse_returnstatus(),

            // RETURNVALUE (0xAC) / PARAM (0xAC)
            0xAC => self.parse_returnvalue(),

            // ENVCHANGE (0xE3)
            0xE3 => self.parse_envchange(),

            // INFO (0xAB)
            0xAB => self.parse_info(),

            // ERROR (0xAA)
            0xAA => self.parse_error(),

            // LOGINACK (0xAD)
            0xAD => self.parse_loginack(),

            // FEATUREEXTACK (0xAE)
            0xAE => self.parse_featureextack(),

            // FEDAUTHINFO (0xEE)
            0xEE => self.parse_fedauthinfo(),

            // SESSIONSTATE (0xE4)
            0xE4 => self.parse_sessionstate(),

            // SSPI (0xED)
            0xED => self.parse_sspi(),

            // ROWFORMAT (0x20)
            0x20 => self.parse_rowformat(),

            _ => Ok(TdsToken::Unknown(token_type)),
        }
    }

    // ================ COL METADATA 解析 ================
    fn parse_colmetadata(&mut self) -> Result<TdsToken, ParserError> {
        let count = self.cursor.get_u16_le() as usize;
        let mut columns = Vec::with_capacity(count);

        for _ in 0..count {
            let user_type = self.cursor.get_u32_le();
            let flags = self.cursor.get_u16_le();
            let col_type = self.parse_data_type()?;
            let col_len = self.parse_type_length(&col_type);

            // 读取列名
            let col_name = self.read_unicode_string()?;

            // 可选的表名和模式名
            let table_name = if flags & 0x10 != 0 {
                Some(self.read_unicode_string()?)
            } else {
                None
            };

            let schema_name = if flags & 0x20 != 0 {
                Some(self.read_unicode_string()?)
            } else {
                None
            };

            // 排序规则
            let collation = if matches!(
                col_type,
                TdsDataType::Char
                    | TdsDataType::Varchar
                    | TdsDataType::Text
                    | TdsDataType::NChar
                    | TdsDataType::NVarchar
                    | TdsDataType::NText
            ) {
                Some(self.parse_collation()?)
            } else {
                None
            };

            columns.push(ColumnMetadata {
                user_type,
                flags,
                col_type,
                col_len,
                col_name,
                table_name,
                schema_name,
                collation,
            });
        }

        Ok(TdsToken::ColMetadata(columns))
    }

    // ================ 行数据解析 ================
    fn parse_row(&mut self) -> Result<TdsToken, ParserError> {
        let _start_pos = self.cursor.position() as usize;
        let mut row_data = Vec::new();

        while self.cursor.has_remaining() {
            let value = self.parse_row_value()?;
            row_data.push(value);
        }

        Ok(TdsToken::Row(row_data))
    }

    fn parse_altrow(&mut self) -> Result<TdsToken, ParserError> {
        let mut row_data = Vec::new();

        while self.cursor.has_remaining() {
            let data_type = self.cursor.get_u8();
            let value = self.parse_value_by_type(data_type)?;
            row_data.push(value);
        }

        Ok(TdsToken::AltRow(row_data))
    }

    fn parse_nbcrow(&mut self) -> Result<TdsToken, ParserError> {
        // 读取空位图
        let null_bitmap_len = (self.cursor.remaining() + 7) / 8;
        let null_bitmap = self.read_bytes(null_bitmap_len)?;

        let mut row_data = Vec::new();
        let mut bitmap_index = 0;
        let mut byte_index = 0;

        // 这里需要知道列数，通常从元数据获取
        // 为简化，假设所有列都有数据
        while self.cursor.has_remaining() {
            let is_null = (null_bitmap[byte_index] >> (7 - bitmap_index)) & 1 == 1;

            if is_null {
                row_data.push(None);
            } else {
                let value = self.parse_row_value()?;
                row_data.push(Some(value));
            }

            bitmap_index += 1;
            if bitmap_index >= 8 {
                bitmap_index = 0;
                byte_index += 1;
            }
        }

        Ok(TdsToken::NBCRow(row_data))
    }

    // ================ 其他 Token 解析 ================
    fn parse_tabname(&mut self) -> Result<TdsToken, ParserError> {
        let name = self.read_unicode_string()?;
        Ok(TdsToken::TabName(name))
    }

    fn parse_colinfo(&mut self) -> Result<TdsToken, ParserError> {
        let count = self.cursor.get_u16_le() as usize;
        let mut colinfos = Vec::with_capacity(count);

        for _ in 0..count {
            let col_num = self.cursor.get_u16_le();
            let table_num = self.cursor.get_u16_le();
            colinfos.push(ColumnInfo { col_num, table_num });
        }

        Ok(TdsToken::ColInfo(colinfos))
    }

    fn parse_order(&mut self) -> Result<TdsToken, ParserError> {
        let count = self.cursor.get_u16_le() as usize;
        let mut orders = Vec::with_capacity(count);

        for _ in 0..count {
            let col_num = self.cursor.get_u16_le();
            orders.push(OrderColumn { col_num });
        }

        Ok(TdsToken::Order(orders))
    }

    fn parse_done(&mut self) -> Result<TdsToken, ParserError> {
        let status = self.cursor.get_u16_le();
        let cur_cmd = self.cursor.get_u16_le();
        let row_count = self.cursor.get_u64_le();

        Ok(TdsToken::Done(DoneStatus {
            status,
            cur_cmd,
            row_count,
        }))
    }

    fn parse_doneproc(&mut self) -> Result<TdsToken, ParserError> {
        let status = self.cursor.get_u16_le();
        let cur_cmd = self.cursor.get_u16_le();
        let row_count = self.cursor.get_u64_le();

        Ok(TdsToken::DoneProc(DoneStatus {
            status,
            cur_cmd,
            row_count,
        }))
    }

    fn parse_doneinproc(&mut self) -> Result<TdsToken, ParserError> {
        let status = self.cursor.get_u16_le();
        let cur_cmd = self.cursor.get_u16_le();
        let row_count = self.cursor.get_u64_le();

        Ok(TdsToken::DoneInProc(DoneStatus {
            status,
            cur_cmd,
            row_count,
        }))
    }

    fn parse_returnstatus(&mut self) -> Result<TdsToken, ParserError> {
        let status = self.cursor.get_i32_le();
        Ok(TdsToken::ReturnStatus(status))
    }

    fn parse_returnvalue(&mut self) -> Result<TdsToken, ParserError> {
        let mut params = Vec::new();

        while self.cursor.has_remaining() {
            let param_name = self.read_unicode_string()?;
            let param_type = self.parse_data_type()?;
            let param_len = self.parse_type_length(&param_type);
            let param_value = self.parse_value_by_type(self.get_type_byte(&param_type)?)?;

            params.push(ReturnParam {
                param_name,
                param_type,
                param_len,
                param_value,
            });
        }

        Ok(TdsToken::ReturnParam(params))
    }

    // ================ ENVCHANGE 解析 ================
    fn parse_envchange(&mut self) -> Result<TdsToken, ParserError> {
        let env_type = self.cursor.get_u8();
        let data_len = self.cursor.get_u16_le() as usize;
        let _old_data = self.read_bytes(data_len)?;
        let new_data = self.read_bytes(data_len)?;

        let env_change = match env_type {
            1 => EnvChange::Database(String::from_utf16_lossy(&bytes_to_u16_vec(&new_data)?)),
            2 => EnvChange::Language(String::from_utf16_lossy(&bytes_to_u16_vec(&new_data)?)),
            3 => EnvChange::CharacterSet(String::from_utf8_lossy(&new_data).to_string()),
            4 => EnvChange::PacketSize(u32::from_le_bytes([
                new_data[0],
                new_data[1],
                new_data[2],
                new_data[3],
            ])),
            5 => EnvChange::UnicodeSorting(new_data[0] != 0),
            6 => EnvChange::UnicodeSortingLocale(u16::from_le_bytes([new_data[0], new_data[1]])),
            7 => EnvChange::SqlCollation(self.parse_collation_from_bytes(&new_data)?),
            8 => EnvChange::BeginTransaction,
            9 => EnvChange::CommitTransaction,
            10 => EnvChange::RollbackTransaction,
            11 => EnvChange::EnlistDTCTransaction,
            13 => EnvChange::DefectTransaction,
            14 => EnvChange::DatabaseMirroringPartner(String::from_utf16_lossy(&bytes_to_u16_vec(
                &new_data,
            )?)),
            15 => EnvChange::PromoteTransaction,
            16 => {
                EnvChange::TransactionManagerAddress(String::from_utf8_lossy(&new_data).to_string())
            }
            17 => EnvChange::TransactionEnded,
            18 => EnvChange::ResetConnection,
            19 => EnvChange::UserInstance,
            20 => EnvChange::Routing(new_data),
            _ => return Err(ParserError::UnknownEnvType(env_type)),
        };

        Ok(TdsToken::EnvChange(env_change))
    }

    // ================ INFO/ERROR 解析 ================
    fn parse_info(&mut self) -> Result<TdsToken, ParserError> {
        let _length = self.cursor.get_u16_le() as usize;
        let number = self.cursor.get_i32_le();
        let state = self.cursor.get_u8();
        let class = self.cursor.get_u8();
        let message = self.read_unicode_string()?;
        let server_name = self.read_unicode_string()?;
        let proc_name = self.read_unicode_string()?;
        let line_number = self.cursor.get_u32_le();

        Ok(TdsToken::Info(InfoMessage {
            number,
            state,
            class,
            message,
            server_name,
            proc_name,
            line_number,
        }))
    }

    fn parse_error(&mut self) -> Result<TdsToken, ParserError> {
        let _length = self.cursor.get_u16_le() as usize;
        let number = self.cursor.get_i32_le();
        let state = self.cursor.get_u8();
        let class = self.cursor.get_u8();
        let message = self.read_unicode_string()?;
        let server_name = self.read_unicode_string()?;
        let proc_name = self.read_unicode_string()?;
        let line_number = self.cursor.get_u32_le();

        Ok(TdsToken::Error(ErrorInfo {
            number,
            state,
            class,
            message,
            server_name,
            proc_name,
            line_number,
        }))
    }

    // ================ 登录相关 Token 解析 ================
    fn parse_loginack(&mut self) -> Result<TdsToken, ParserError> {
        let _length = self.cursor.get_u16_le() as usize;
        let interface = self.cursor.get_u8();
        let tds_version = self.cursor.get_u32();
        let prog_name = self.read_unicode_string()?;
        let prog_version = self.cursor.get_u32();

        Ok(TdsToken::LoginAck(LoginAck {
            interface,
            tds_version,
            prog_name,
            prog_version,
        }))
    }

    fn parse_featureextack(&mut self) -> Result<TdsToken, ParserError> {
        let mut features = Vec::new();

        while self.cursor.has_remaining() {
            let feature_id = self.cursor.get_u8();
            let feature_len = self.cursor.get_u32_le() as usize;
            let feature_data = self.read_bytes(feature_len)?;

            features.push(Feature {
                id: feature_id,
                data: feature_data,
            });
        }

        Ok(TdsToken::FeatureExtAck(FeatureExtAck { features }))
    }

    fn parse_fedauthinfo(&mut self) -> Result<TdsToken, ParserError> {
        let sts_url = self.read_unicode_string()?;
        let spn = self.read_unicode_string()?;

        Ok(TdsToken::FedAuthInfo(FedAuthInfo { sts_url, spn }))
    }

    fn parse_sessionstate(&mut self) -> Result<TdsToken, ParserError> {
        let state = self.cursor.get_u32_le();
        let data_len = self.cursor.get_u32_le() as usize;
        let data = self.read_bytes(data_len)?;

        Ok(TdsToken::SessionState(SessionState { state, data }))
    }

    fn parse_sspi(&mut self) -> Result<TdsToken, ParserError> {
        let data = self.read_bytes(self.cursor.remaining())?;
        Ok(TdsToken::Sspi(data))
    }

    fn parse_rowformat(&mut self) -> Result<TdsToken, ParserError> {
        let format = self.cursor.get_u8();
        Ok(TdsToken::RowFormat(format))
    }

    // ================ 辅助解析函数 ================
    fn parse_data_type(&mut self) -> Result<TdsDataType, ParserError> {
        let type_byte = self.cursor.get_u8();

        match type_byte {
            0x1F => Ok(TdsDataType::Null),
            0x30 => Ok(TdsDataType::TinyInt),
            0x34 => Ok(TdsDataType::SmallInt),
            0x38 => Ok(TdsDataType::Int),
            0x7F => Ok(TdsDataType::BigInt),
            0x3B => Ok(TdsDataType::Float4),
            0x3C => Ok(TdsDataType::Float8),
            0x3E => Ok(TdsDataType::Money),
            0x7A => Ok(TdsDataType::Money4),
            0x3D => Ok(TdsDataType::DateTime),
            0x3A => Ok(TdsDataType::DateTime4),
            0x37 => Ok(TdsDataType::Decimal),
            0x3F => Ok(TdsDataType::Numeric),
            0x32 => Ok(TdsDataType::Bit),
            0x24 => Ok(TdsDataType::Guid),
            0x26 => Ok(TdsDataType::Intn),
            0x6A => Ok(TdsDataType::Decimaln),
            0x6C => Ok(TdsDataType::Numericn),
            0x6D => Ok(TdsDataType::Floatn),
            0x6E => Ok(TdsDataType::Moneyn),
            0x6F => Ok(TdsDataType::Datetimen),
            0x2F => Ok(TdsDataType::Char),
            0x27 => Ok(TdsDataType::Varchar),
            0x2D => Ok(TdsDataType::Binary),
            0x25 => Ok(TdsDataType::Varbinary),
            0xEF => Ok(TdsDataType::NChar),
            0xE7 => Ok(TdsDataType::NVarchar),
            0x23 => Ok(TdsDataType::Text),
            0x63 => Ok(TdsDataType::NText),
            0x22 => Ok(TdsDataType::Image),
            _ => Ok(TdsDataType::VarLenType(type_byte)),
        }
    }

    fn parse_row_value(&mut self) -> Result<RowValue, ParserError> {
        let type_byte = self.cursor.get_u8();
        self.parse_value_by_type(type_byte)
    }

    fn parse_value_by_type(&mut self, type_byte: u8) -> Result<RowValue, ParserError> {
        match type_byte {
            // NULL
            0x1F => Ok(RowValue::Null),

            // TINYINT
            0x30 => Ok(RowValue::TinyInt(self.cursor.get_u8())),

            // SMALLINT
            0x34 => Ok(RowValue::SmallInt(self.cursor.get_i16_le())),

            // INT
            0x38 => Ok(RowValue::Int(self.cursor.get_i32_le())),

            // BIGINT
            0x7F => Ok(RowValue::BigInt(self.cursor.get_i64_le())),

            // FLOAT4
            0x3B => Ok(RowValue::Float4(self.cursor.get_f32_le())),

            // FLOAT8
            0x3C => Ok(RowValue::Float8(self.cursor.get_f64_le())),

            // BIT
            0x32 => Ok(RowValue::Bit(self.cursor.get_u8() != 0)),

            // DATETIME
            0x3D => {
                let days = self.cursor.get_i32_le();
                let minutes = self.cursor.get_u32_le();
                let datetime = tds_datetime_to_chrono(days, minutes);
                Ok(RowValue::DateTime(datetime))
            }

            // DATETIME4
            0x3A => {
                let days = self.cursor.get_u16_le() as i32;
                let minutes = self.cursor.get_u16_le() as u32;
                let datetime = tds_datetime_to_chrono(days, minutes);
                Ok(RowValue::DateTime(datetime))
            }

            // GUID
            0x24 => {
                let data = self.read_bytes(16)?;
                let guid = u128::from_le_bytes([
                    data[3], data[2], data[1], data[0], data[5], data[4], data[7], data[6],
                    data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
                ]);
                Ok(RowValue::Guid(guid))
            }

            // NVARCHAR / VARCHAR
            0xE7 | 0x27 => {
                let len = self.cursor.get_u16_le() as usize;
                let data = self.read_bytes(len)?;
                let string = if type_byte == 0xE7 {
                    String::from_utf16_lossy(&bytes_to_u16_vec(&data)?)
                } else {
                    String::from_utf8_lossy(&data).to_string()
                };
                Ok(RowValue::UnicodeString(string))
            }

            // NCHAR / CHAR
            0xEF | 0x2F => {
                let len = self.cursor.get_u16_le() as usize;
                let data = self.read_bytes(len)?;
                let string = if type_byte == 0xEF {
                    String::from_utf16_lossy(&bytes_to_u16_vec(&data)?)
                } else {
                    String::from_utf8_lossy(&data).to_string()
                };
                Ok(RowValue::String(string))
            }

            // BINARY / VARBINARY
            0x2D | 0x25 => {
                let len = self.cursor.get_u16_le() as usize;
                let data = self.read_bytes(len)?;
                Ok(RowValue::Binary(data))
            }

            // MONEY
            0x3E => {
                let high = self.cursor.get_i32_le();
                let low = self.cursor.get_u32_le();
                let value = ((high as i64) << 32) | (low as i64);
                Ok(RowValue::Money(value))
            }

            // DECIMAL / NUMERIC
            0x37 | 0x3F => {
                let len = self.cursor.get_u8() as usize;
                let scale = self.cursor.get_u8();
                let data = self.read_bytes(len)?;
                if type_byte == 0x37 {
                    Ok(RowValue::Decimal(data, scale))
                } else {
                    Ok(RowValue::Numeric(data, scale))
                }
            }

            _ => {
                // 未知类型，读取剩余数据
                let data = self.read_bytes(self.cursor.remaining())?;
                Ok(RowValue::Unknown(type_byte, data))
            }
        }
    }

    fn parse_collation(&mut self) -> Result<Collation, ParserError> {
        let lcid = self.cursor.get_u32_le();
        let flags = self.cursor.get_u16_le();
        let version = self.cursor.get_u8();
        let sort_id = self.cursor.get_u8();

        Ok(Collation {
            lcid,
            flags,
            version,
            sort_id,
        })
    }

    fn parse_collation_from_bytes(&self, data: &[u8]) -> Result<Collation, ParserError> {
        if data.len() < 6 {
            return Err(ParserError::InvalidData);
        }

        let lcid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let flags = u16::from_le_bytes([data[4], data[5]]);
        let version = if data.len() > 6 { data[6] } else { 0 };
        let sort_id = if data.len() > 7 { data[7] } else { 0 };

        Ok(Collation {
            lcid,
            flags,
            version,
            sort_id,
        })
    }

    fn read_unicode_string(&mut self) -> Result<String, ParserError> {
        let len = self.cursor.get_u16_le() as usize;
        if len == 0 {
            return Ok(String::new());
        }

        let data = self.read_bytes(len * 2)?;
        let utf16_chars: Vec<u16> = data
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();

        String::from_utf16(&utf16_chars).map_err(ParserError::Utf16Error)
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, ParserError> {
        if len > self.cursor.remaining() {
            return Err(ParserError::InsufficientData);
        }

        let mut buf = vec![0u8; len];
        self.cursor.copy_to_slice(&mut buf);
        Ok(buf)
    }

    fn parse_type_length(&self, data_type: &TdsDataType) -> u16 {
        match data_type {
            TdsDataType::TinyInt => 1,
            TdsDataType::SmallInt => 2,
            TdsDataType::Int => 4,
            TdsDataType::BigInt => 8,
            TdsDataType::Float4 => 4,
            TdsDataType::Float8 => 8,
            TdsDataType::Bit => 1,
            TdsDataType::DateTime => 8,
            TdsDataType::DateTime4 => 4,
            TdsDataType::Guid => 16,
            TdsDataType::Money => 8,
            TdsDataType::Money4 => 4,
            _ => 0, // 可变长度类型
        }
    }

    fn get_type_byte(&self, data_type: &TdsDataType) -> Result<u8, ParserError> {
        match data_type {
            TdsDataType::Null => Ok(0x1F),
            TdsDataType::TinyInt => Ok(0x30),
            TdsDataType::SmallInt => Ok(0x34),
            TdsDataType::Int => Ok(0x38),
            TdsDataType::BigInt => Ok(0x7F),
            TdsDataType::Float4 => Ok(0x3B),
            TdsDataType::Float8 => Ok(0x3C),
            TdsDataType::Bit => Ok(0x32),
            TdsDataType::DateTime => Ok(0x3D),
            TdsDataType::DateTime4 => Ok(0x3A),
            TdsDataType::Guid => Ok(0x24),
            TdsDataType::Money => Ok(0x3E),
            TdsDataType::Money4 => Ok(0x7A),
            TdsDataType::NVarchar => Ok(0xE7),
            TdsDataType::Varchar => Ok(0x27),
            TdsDataType::NChar => Ok(0xEF),
            TdsDataType::Char => Ok(0x2F),
            TdsDataType::Binary => Ok(0x2D),
            TdsDataType::Varbinary => Ok(0x25),
            TdsDataType::Decimal => Ok(0x37),
            TdsDataType::Numeric => Ok(0x3F),
            _ => Err(ParserError::UnsupportedDataType),
        }
    }

    fn parse_packet_data_stream_headers(&mut self) -> Result<(), ParserError> {
        if self.cursor.remaining() <= 4 {
            return Err(ParserError::InsufficientData);
        }

        let mut total_length = self.cursor.get_u32_le() as isize;
        while self.cursor.remaining() >= 18 && total_length > 0 {
            let length = self.cursor.get_u32_le() as isize;
            self.cursor.seek(SeekFrom::Current(length as i64))?;
            total_length -= length;
        }

        Ok(())
    }

    fn parse_sql_batch(&mut self) -> Result<String, ParserError> {
        if self.cursor.remaining() < 22 {
            return Err(ParserError::InsufficientData);
        }
        let length = self.cursor.get_u32_le();
        let payload = if length == 22 && self.cursor.remaining() > 18 {
            self.cursor.seek(SeekFrom::Current(18))?;
            self.cursor.get_ref()
        } else {
            self.cursor.get_ref()
        };

        decode_sql_text(payload)
    }

    fn read_type_info(&mut self, data_type: u8) -> Result<(u16, u8, u8), ParserError> {
        let mut max_length = 0u16;
        let mut precision = 0u8;
        let mut scale = 0u8;

        match DataType::from(data_type) {
            DataType::VarChar | DataType::NVarChar | DataType::VarBinary => {
                max_length = self.cursor.get_u16_le();
            }
            DataType::Decimal | DataType::Numeric => {
                max_length = self.cursor.get_u8() as u16;
                precision = self.cursor.get_u8();
                scale = self.cursor.get_u8();
            }
            DataType::Char | DataType::NChar | DataType::Binary => {
                max_length = self.cursor.get_u16_le();
            }
            _ => {
                // 对于其他类型，使用默认值
            }
        }

        Ok((max_length, precision, scale))
    }

    fn parse_rpc_parameter_value(
        &mut self,
        data_type: &DataType,
        _max_length: u16,
    ) -> Result<ParameterValue, ParserError> {
        let data_length = self.cursor.get_u16_le() as usize;

        if data_length == 0 {
            return Ok(ParameterValue::Null);
        }

        match data_type {
            DataType::TinyInt => {
                let value = self.cursor.get_u8();
                Ok(ParameterValue::TinyInt(value))
            }
            DataType::Bit => {
                let value = self.cursor.get_u8() != 0;
                Ok(ParameterValue::Bit(value))
            }
            DataType::SmallInt => {
                let value = self.cursor.get_i16_le();
                Ok(ParameterValue::SmallInt(value))
            }
            DataType::Int => {
                let value = self.cursor.get_i32_le();
                Ok(ParameterValue::Int(value))
            }
            DataType::BigInt => {
                let value = self.cursor.get_i64_le();
                Ok(ParameterValue::BigInt(value))
            }
            DataType::Real => {
                let value = self.cursor.get_f32_le();
                Ok(ParameterValue::Real(value))
            }
            DataType::Float => {
                let value = self.cursor.get_f64_le();
                Ok(ParameterValue::Float(value))
            }
            DataType::VarChar | DataType::Char => {
                let bytes = self.read_bytes(data_length)?;
                let string = String::from_utf8(bytes)?;
                Ok(ParameterValue::String(string))
            }
            DataType::NVarChar | DataType::NChar => {
                // Unicode 字符串，每个字符2字节
                let char_count = data_length / 2;
                let mut string = String::with_capacity(char_count);

                for _ in 0..char_count {
                    let ch = self.cursor.get_u16_le();
                    if let Some(c) = char::from_u32(ch as u32) {
                        string.push(c);
                    }
                }

                Ok(ParameterValue::String(string))
            }
            DataType::VarBinary | DataType::Binary => {
                let bytes = self.read_bytes(data_length as usize)?;
                Ok(ParameterValue::Binary(bytes))
            }
            DataType::Null => Ok(ParameterValue::Null),
            _ => {
                // 对于不支持的类型，直接读取原始字节
                let bytes = self.read_bytes(data_length as usize)?;
                Ok(ParameterValue::Other(bytes))
            }
        }
    }

    fn parse_rpc_parameter(&mut self) -> Result<RpcParameter, ParserError> {
        let name_length = self.cursor.get_u8();
        let name_bytes = self.read_bytes(name_length as usize)?;
        let name = String::from_utf8(name_bytes)?;

        let status = ParamStatus::from(self.cursor.get_u8());
        let data_type_byte = self.cursor.get_u8();
        let data_type = DataType::from(data_type_byte);

        let (max_length, precision, scale) = self.read_type_info(data_type_byte)?;

        let value = self.parse_rpc_parameter_value(&data_type, max_length)?;

        Ok(RpcParameter {
            name,
            status,
            data_type,
            max_length,
            precision,
            scale,
            value,
        })
    }

    fn parse_rpc(&mut self) -> Result<String, ParserError> {
        self.parse_packet_data_stream_headers()?;

        if self.cursor.remaining() < 6 {
            return Err(ParserError::InsufficientData);
        }
        let _procedure_name_length = self.cursor.get_u16_le();
        let _procedure_id = self.cursor.get_u16_le();
        let _options = self.cursor.get_u16_le();

        let mut parameters = Vec::new();
        // 解析参数
        while self.cursor.remaining() > 0 {
            // 检查是否还有数据可以解析
            parameters.push(self.parse_rpc_parameter()?);
        }

        Ok(parameters
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(","))
    }

    pub fn parse(&mut self) -> Result<(), ParserError> {
        let header = self.parse_header()?;

        match header.packet_type {
            1 => {
                self.sql = Some(self.parse_sql_batch()?);
            }
            3 => {
                self.sql = Some(self.parse_rpc()?);
            }
            4 => {
                while self.cursor.has_remaining() {
                    match self.parse_token()? {
                        TdsToken::Done(done) => {
                            if done.is_valid_row_count() {
                                self.affected_row = Some(done.row_count);
                            }
                        }
                        TdsToken::DoneInProc(done) => {
                            if done.is_valid_row_count() {
                                self.affected_row = Some(done.row_count);
                            }
                        }
                        TdsToken::ReturnStatus(code) => {
                            self.status_code = Some(code);
                        }
                        TdsToken::Error(e) => {
                            self.error_message = Some(e.message);
                        }
                        _ => {}
                    }
                }
            }
            _ => return Err(ParserError::InvalidData),
        }
        Ok(())
    }
}

fn tds_datetime_to_chrono(days: i32, minutes: u32) -> NaiveDateTime {
    let base_date = NaiveDate::from_ymd_opt(1900, 1, 1).unwrap();
    let date = base_date
        .checked_add_days(chrono::Days::new(days as u64))
        .unwrap_or(base_date);
    let time =
        NaiveTime::from_num_seconds_from_midnight_opt(((minutes as u64 * 60) % 86400) as u32, 0)
            .unwrap_or(NaiveTime::MIN);

    NaiveDateTime::new(date, time)
}

fn bytes_to_u16_vec(data: &[u8]) -> Result<Vec<u16>, ParserError> {
    if data.len() % 2 != 0 {
        return Err(ParserError::InvalidData);
    }

    Ok(data
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect())
}

fn decode_sql_text(bytes: &[u8]) -> Result<String, ParserError> {
    // SQL Batch 中的文本通常是 UTF-16LE
    if bytes.len() % 2 == 0 {
        // 尝试解码为 UTF-16LE
        if let Ok(text) = decode_utf16le(bytes) {
            return Ok(text);
        }
    }

    // 回退到 UTF-8
    String::from_utf8(bytes.to_vec()).map_err(ParserError::Utf8Error)
}

fn decode_utf16le(bytes: &[u8]) -> Result<String, ParserError> {
    let utf16_chars: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    String::from_utf16(&utf16_chars).map_err(ParserError::Utf16Error)
}

#[derive(Debug)]
pub enum ParserError {
    IoError(std::io::Error),
    UnknownToken(u8),
    UnknownEnvType(u8),
    InvalidData,
    InsufficientData,
    Utf8Error(std::string::FromUtf8Error),
    Utf16Error(std::string::FromUtf16Error),
    UnsupportedDataType,
}

impl From<std::io::Error> for ParserError {
    fn from(err: std::io::Error) -> Self {
        ParserError::IoError(err)
    }
}

impl From<std::string::FromUtf8Error> for ParserError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        ParserError::Utf8Error(err)
    }
}

impl From<std::string::FromUtf16Error> for ParserError {
    fn from(err: std::string::FromUtf16Error) -> Self {
        ParserError::Utf16Error(err)
    }
}

mod tests {
    #[test]
    fn token() -> Result<(), ParserError> {
        // 示例：解析 TDS 响应
        let data = &[
            // COL METADATA token
            0x81, 0x02, 0x00, // token type + column count
            // 第一列
            0x00, 0x00, 0x00, 0x00, // user_type
            0x00, 0x00, // flags
            0x38, // INT type
            0x04, 0x00, // length
            0x02, 0x00, // name length (2 chars)
            0x69, 0x00, 0x64, 0x00, // "id" in UTF-16LE
            // 第二列
            0x00, 0x00, 0x00, 0x00, // user_type
            0x00, 0x00, // flags
            0xE7, // NVARCHAR type
            0x00, 0x00, // length (variable)
            0x08, 0x00, // name length (4 chars)
            0x6E, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x65, 0x00, // "name" in UTF-16LE
        ];

        let mut parser = TdsParser::new(data);
        let token = parser.parse_token()?;

        match token {
            TdsToken::ColMetadata(columns) => {
                for (i, col) in columns.iter().enumerate() {
                    println!("Column {}: {}", i + 1, col.col_name);
                    println!("  Type: {:?}", col.col_type);
                    println!("  Length: {}", col.col_len);
                }
            }
            _ => println!("Unexpected token: {:?}", token),
        }

        Ok(())
    }
}
