pub const PROTOCOL_VERSION: u8 = 10;

// Header
pub const HEADER_LEN: usize = 4;

pub const HEADER_OFFSET: usize = 0;
pub const NUMBER_OFFSET: usize = 3;

// Greeting
pub const SERVER_VERSION_EOF: u8 = 0;

pub const PROTOCOL_VERSION_LEN: usize = 1;
pub const THREAD_ID_LEN: usize = 4;

pub const PROTOCOL_VERSION_OFFSET: usize = 0;
pub const SERVER_VERSION_OFFSET: usize = PROTOCOL_VERSION_OFFSET + PROTOCOL_VERSION_LEN;
pub const THREAD_ID_OFFSET_B: usize = SERVER_VERSION_OFFSET;

// Request
pub const COMMAND_OFFSET: usize = 0;
pub const COMMAND_LEN: usize = 1;

// Response
pub const RESPONSE_CODE_LEN: usize = 1;
pub const ERROR_CODE_LEN: usize = 2;
pub const AFFECTED_ROWS_LEN: usize = 1;
pub const SQL_STATE_LEN: usize = 6;
pub const SQL_STATE_MARKER: u8 = b'#';

pub const RESPONSE_CODE_OFFSET: usize = 0;
pub const ERROR_CODE_OFFSET: usize = RESPONSE_CODE_OFFSET + RESPONSE_CODE_LEN;
pub const AFFECTED_ROWS_OFFSET: usize = RESPONSE_CODE_OFFSET + RESPONSE_CODE_LEN;
pub const SQL_STATE_OFFSET: usize = ERROR_CODE_OFFSET + ERROR_CODE_LEN;

// int
pub const INT_FLAGS_2: u8 = 0xfc;
pub const INT_FLAGS_3: u8 = 0xfd;
pub const INT_FLAGS_8: u8 = 0xfe;

pub const INT_BASE_LEN: usize = 1;

pub const MYSQL_RESPONSE_CODE_OK: u8 = 0;
pub const MYSQL_RESPONSE_CODE_ERR: u8 = 0xff;
pub const MYSQL_RESPONSE_CODE_EOF: u8 = 0xfe;

pub const MYSQL_COMMAND_QUIT: u8 = 1;
pub const MYSQL_COMMAND_USE_DATABASE: u8 = 2;
pub const MYSQL_COMMAND_QUERY: u8 = 3;
pub const MYSQL_COMMAND_SHOW_FIELD: u8 = 4;
pub const MYSQL_COMMAND_MAX: u8 = 5;
