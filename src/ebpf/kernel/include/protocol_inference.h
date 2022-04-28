#ifndef __BPF_PROTO_INFER_H__
#define __BPF_PROTO_INFER_H__

#include "common.h"
#include "socket_trace.h"

static __inline bool is_socket_info_valid(struct socket_info_t *sk_info)
{
	return (sk_info != NULL && sk_info->uid != 0);
}

static __inline int is_http_response(const char *data)
{
	return (data[0] == 'H' && data[1] == 'T' && data[2] == 'T'
		&& data[3] == 'P' && data[4] == '/' && data[5] == '1'
		&& data[6] == '.' && data[8] == ' ');
}

static __inline int is_http_request(const char *data, int data_len)
{
	switch (data[0]) {
		/* DELETE */
	case 'D':
		if ((data[1] != 'E') || (data[2] != 'L') || (data[3] != 'E')
		    || (data[4] != 'T') || (data[5] != 'E')
		    || (data[6] != ' ')) {
			return 0;
		}
		break;

		/* GET */
	case 'G':
		if ((data[1] != 'E') || (data[2] != 'T') || (data[3] != ' ')) {
			return 0;
		}
		break;

		/* HEAD */
	case 'H':
		if ((data[1] != 'E') || (data[2] != 'A') || (data[3] != 'D')
		    || (data[4] != ' ')) {
			return 0;
		}
		break;

		/* OPTIONS */
	case 'O':
		if (data_len < 8 || (data[1] != 'P') || (data[2] != 'T')
		    || (data[3] != 'I') || (data[4] != 'O') || (data[5] != 'N')
		    || (data[6] != 'S') || (data[7] != ' ')) {
			return 0;
		}
		break;

		/* PATCH/POST/PUT */
	case 'P':
		switch (data[1]) {
		case 'A':
			if ((data[2] != 'T') || (data[3] != 'C')
			    || (data[4] != 'H') || (data[5] != ' ')) {
				return 0;
			}
			break;
		case 'O':
			if ((data[2] != 'S') || (data[3] != 'T')
			    || (data[4] != ' ')) {
				return 0;
			}
			break;
		case 'U':
			if ((data[2] != 'T') || (data[3] != ' ')) {
				return 0;
			}
			break;
		default:
			return 0;
		}
		break;

	default:
		return 0;
	}

	return 1;
}

// https://tools.ietf.org/html/rfc7540#section-4.1
// +-----------------------------------------------+
// |                 Length (24)                   |
// +---------------+---------------+---------------+
// |   Type (8)    |   Flags (8)   |
// +-+-------------+---------------+-------------------------------+
// |R|                 Stream Identifier (31)                      |
// +=+=============================================================+
// |                   Frame Payload (0...)                      ...
// +---------------------------------------------------------------+
// Frame Payload (0...)
// request:
//      1       :authority
//      2       :method GET
//      3       :method POST
// others as response.
static __inline enum message_type parse_http2_headers_frame(const char *buf_src,
							    size_t count)
{
#define HTTPV2_FRAME_PROTO_SZ           0x9
#define HTTPV2_FRAME_READ_SZ            0xa
#define HTTPV2_FRAME_TYPE_HEADERS       0x1
#define HTTPV2_STATIC_TABLE_AUTH_IDX    0x1
#define HTTPV2_STATIC_TABLE_GET_IDX     0x2
#define HTTPV2_STATIC_TABLE_POST_IDX    0x3
#define HTTPV2_LOOP_MAX 10

	// fixed 9-octet header
	if (count < HTTPV2_FRAME_PROTO_SZ)
		return MSG_UNKNOWN;

	__u32 offset = 0;
	__u8 type = 0, flags_unset = 0, reserve = 0, static_table_idx, i;
	__u8 msg_type = MSG_UNKNOWN;
	__u8 buf[HTTPV2_FRAME_READ_SZ] = { 0 };
	bool is_valid_len = false;

#pragma unroll
	for (i = 0; i < HTTPV2_LOOP_MAX; i++) {
		if (offset == count) {
			is_valid_len = true;
			break;
		}

		if (offset + HTTPV2_FRAME_READ_SZ > count)
			return MSG_UNKNOWN;

		bpf_probe_read(buf, sizeof(buf), buf_src + offset);
		offset += (__bpf_ntohl(*(__u32 *) buf) >> 8) +  
			HTTPV2_FRAME_PROTO_SZ;
		type = buf[3];
		flags_unset = buf[4] & 0xd2;
		reserve = buf[5] & 0x01;
		static_table_idx = buf[9] & 0x7f;
		if (type == HTTPV2_FRAME_TYPE_HEADERS) {
			if (flags_unset || reserve)
				return MSG_UNKNOWN;
			if (static_table_idx == HTTPV2_STATIC_TABLE_AUTH_IDX ||
			    static_table_idx == HTTPV2_STATIC_TABLE_GET_IDX ||
			    static_table_idx == HTTPV2_STATIC_TABLE_POST_IDX)
				msg_type = MSG_REQUEST;
			else
				msg_type = MSG_RESPONSE;
		}
	}

	if (!is_valid_len)
		msg_type = MSG_UNKNOWN;

	return msg_type;
}

static __inline enum message_type infer_http2_message(const char *buf_src,
						      size_t count,
						      struct conn_info_t
						      *conn_info)
{
	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_HTTP2)
			return MSG_UNKNOWN;
	}

	return parse_http2_headers_frame(buf_src, count);
}

static __inline enum message_type infer_http_message(const char *buf,
						     size_t count,
						     struct conn_info_t
						     *conn_info)
{
	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_HTTP1)
			return MSG_UNKNOWN;
	}
	// HTTP/1.1 200 OK\r\n (HTTP response is 17 characters)
	// GET x HTTP/1.1\r\n (HTTP response is 16 characters)
	// MAY be without "OK", ref:https://www.rfc-editor.org/rfc/rfc7231
	if (count < 14) {
		return MSG_UNKNOWN;
	}

	if (is_http_response(buf)) {
		return MSG_RESPONSE;
	}

	if (is_http_request(buf, count)) {
		return MSG_REQUEST;
	}

	return MSG_UNKNOWN;
}

// MySQL packet:
//      0         8        16        24        32
//      +---------+---------+---------+---------+
//      |        payload_length       | seq_id  |
//      +---------+---------+---------+---------+
//      |                                       |
//      .            ...  body ...              .
//      .                                       .
//      .                                       .
//      +----------------------------------------
// ref : https://dev.mysql.com/doc/internals/en/com-process-kill.html
static __inline enum message_type infer_mysql_message(const char *buf,
						      size_t count,
						      struct conn_info_t
						      *conn_info)
{
#define  kComQuery 0x03
#define  kComConnect 0x0b
#define  kComStmtPrepare 0x16
#define  kComStmtExecute 0x17
#define  kComStmtClose   0x19

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_MYSQL)
			return MSG_UNKNOWN;
	}

	if (conn_info->sk != NULL) {
		__u32 len;
		__u8 seq, com;

		len = *((__u32 *) buf) & 0x00ffffff;
		seq = buf[3];
		com = buf[4];

		if (conn_info->prev_count == 4) {
			len = *(__u32 *) conn_info->prev_buf & 0x00ffffff;
			if (len == count) {
				seq = conn_info->prev_buf[3];
				count += 4;
				com = buf[0];
			}
		}

		if (count < 5 || len == 0)
			return MSG_UNKNOWN;

		if (is_socket_info_valid(conn_info->socket_info_ptr)) {
			if (seq == 0)
				return MSG_REQUEST;
			else if (seq == 1)
				return MSG_RESPONSE;
			else
				return MSG_UNKNOWN;
		}

		if (seq == 0) {
			// 请求长度判断来提高推断准确率。
			if (len > 10000) {
				return MSG_UNKNOWN;
			}

			if (com == kComConnect || com == kComQuery
			    || com == kComStmtPrepare || com == kComStmtExecute
			    || com == kComStmtClose) {
				return MSG_REQUEST;
			}
		}
	}

	return MSG_UNKNOWN;

	/*
	   e.g:
	   -----------------------------------------------------------
	   Query:
	   MySQL Protocol
	   Packet Length: 33 (21 00 00) ------>  先读取这四个字节
	   Packet Number: 0  (00) ------------>  /
	   ---------------------------------- 下面这些下一次读取
	   Request Command Query
	   Command: Query (3) (03)
	   Statement: select user,host from mysql.user
	   -----------------------------------------------------------
	   Response:
	   MySQL Protocol
	   Packet Length: 1
	   Packet Number: 1
	   Number of fields: 2
	   MySQL Protocol
	   Packet Length: 43
	   Packet Number: 2
	   Catalog: def
	   Database: mysql
	   Table: user
	   Original table: user
	   Name: user
	   Original name: User
	   Charset number: utf8 COLLATE utf8_general_ci (33)
	   Length: 48
	   Type: FIELD_TYPE_STRING (254)
	   Flags: 0x4083
	   Decimals: 0
	   MySQL Protocol
	   Packet Length: 43
	   Packet Number: 3
	   Catalog: def
	   Database: mysql
	   Table: user
	   Original table: user
	   Name: host
	   Original name: Host
	 */
}

/*
0                   15 16                     31
|---------------------|-----------------------|
|    标识 ID          |     标志 flags        |
|---------------------|-----------------------|
|    问题数           |    资源记录数         |
|---------------------|-----------------------|
|    授权资源记录数   |    附加资源记录数     |
|---------------------|-----------------------|
*/
struct dns_header {
	unsigned short id;	// identification number

	unsigned char rd:1;	// recursion desired
	unsigned char tc:1;	// truncated message
	unsigned char aa:1;	// authoritive answer
	unsigned char opcode:4;	// purpose of message
	unsigned char qr:1;	// query/response flag

	unsigned char rcode:4;	// response code
	unsigned char cd:1;	// checking disabled
	unsigned char ad:1;	// authenticated data
	unsigned char z:1;	// its z! reserved
	unsigned char ra:1;	// recursion available

	unsigned short q_count;	// number of question entries
	unsigned short ans_count;	// number of answer entries
	unsigned short auth_count;	// number of authority entries
	unsigned short add_count;	// number of resource entries
};

static __inline enum message_type infer_dns_message(const char *buf,
						    size_t count,
						    struct conn_info_t
						    *conn_info)
{
	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_DNS)
			return MSG_UNKNOWN;
	}

	const int dns_header_size = 12;

	// This is the typical maximum size for DNS.
	const int dns_msg_max_size = 512;

	// Maximum number of resource records.
	// https://stackoverflow.com/questions/6794926/how-many-a-records-can-fit-in-a-single-dns-response
	const int max_num_rr = 25;

	if (count < dns_header_size || count > dns_msg_max_size) {
		return MSG_UNKNOWN;
	}

	struct dns_header *dns = (struct dns_header *)buf;

	__u16 num_questions = __bpf_ntohs(dns->q_count);
	__u16 num_answers = __bpf_ntohs(dns->ans_count);
	__u16 num_auth = __bpf_ntohs(dns->auth_count);
	__u16 num_addl = __bpf_ntohs(dns->add_count);

	bool qr = dns->qr;	// QR（Response）：查询请求/响应的标志信息。查询请求时，值为 0；响应时，值为 1。
	__u8 opcode = dns->opcode;	// 操作码。其中，0 表示标准查询；1 表示反向查询；2 表示服务器状态请求。
	__u8 zero = dns->z;	// Z：保留字段，在所有的请求和应答报文中，它的值必须为 0。
	if (zero != 0) {
		return MSG_UNKNOWN;
	}

	if (opcode != 0) {	//非标准查询不予处理
		return MSG_UNKNOWN;
	}

	if (num_questions == 0 || num_questions > 10) {
		return MSG_UNKNOWN;
	}

	__u32 num_rr = num_questions + num_answers + num_auth + num_addl;
	if (num_rr > max_num_rr) {
		return MSG_UNKNOWN;
	}

	return (qr == 0) ? MSG_REQUEST : MSG_RESPONSE;
}

static __inline bool is_include_crlf(const char *buf)
{
#define PARAMS_LIMIT 20

	int i;
#pragma unroll
	for (i = 1; i < PARAMS_LIMIT; ++i) {
		if (buf[i] == '\r')
			break;
	}

	if (i == PARAMS_LIMIT)
		return false;

	i++;
	if (buf[i] != '\n')
		return false;

	return true;
}

// http://redisdoc.com/topic/protocol.html
static __inline enum message_type infer_redis_message(const char *buf,
						      size_t count,
						      struct conn_info_t
						      *conn_info)
{
	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_REDIS)
			return MSG_UNKNOWN;
	}

	const char first_byte = buf[0];

	if (	   // 对于简单字符串，回复的第一个字节是“+”
		   first_byte != '+' &&
		   // 对于错误，回复的第一个字节是“-”
		   first_byte != '-' &&
		   // 对于整数，回复的第一个字节是“：”
		   first_byte != ':' &&
		   // 对于批量字符串，回复的第一个字节是“$”
		   first_byte != '$' &&
		   // 对于数组，回复的第一个字节是“ *”
		   first_byte != '*') {
		return MSG_UNKNOWN;
	}

	if (first_byte == '*') {
		if (is_include_crlf(buf))
			return MSG_REQUEST;
	} else {
		//-ERR unknown command 'foobar'
		//-WRONGTYPE Operation against a key holding the wrong kind of value
		if (first_byte == '-') {
			if ((buf[1] != 'E' && buf[1] != 'W') || buf[2] != 'R')
				return MSG_UNKNOWN;
			else
				return MSG_RESPONSE;
		} else {
			if (is_include_crlf(buf))
				return MSG_RESPONSE;
		}
	}

	return MSG_UNKNOWN;
}

/*
 * https://dubbo.apache.org/zh/blog/2018/10/05/dubbo-%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/
 * 0                                                                                       31
 * |   1byte      |   1byte     |                  1 byte               |      1 byte      |
 * ---------------|-------------|---------------------------------------|------------------|
 * |              |             | 1bit  | 1bit | 1bit  |      5bit      |                  |
 * | Magic High   |  Magic Low  |Req/Res| 2way | Event | Serializion ID |      status      |
 * -----------------------------------------------------------------------------------------
 *
 * 32                                                                                      63
 * |-------------------------------------------------------------------------------------- |
 * 64                                Request ID (8 bytes)                                  95
 * |---------------------------------------------------------------------------------------|
 *
 * 96                                                                                      127
 * |---------------------------------Body Length (4 bytes)---------------------------------|
 *
 * | -------------------------------- Body (n bytes) --------------------------------------|
 *
 * 16字节头 header
 * - Magic High & Magic Low (16 bits) 标识协议版本号，Dubbo 协议：0xdabb
 * - Req/Res (1 bit) 标识是请求或响应。请求： 1; 响应： 0。
 * - 2 Way (1 bit) 仅在 Req/Res 为1（请求）时才有用，标记是否期望从服务器返回值。如果需要来自服务器的返回值，则设置为1。
 * - Event (1 bit) 标识是否是事件消息，例如，心跳事件。如果这是一个事件，则设置为1。
 * - Serialization ID (5 bit) 标识序列化类型：比如 fastjson 的值为6。
 * - Status (8 bits) 仅在 Req/Res 为0（响应）时有用，用于标识响应的状态。
 *     20 - OK
 *     30 - CLIENT_TIMEOUT
 *     31 - SERVER_TIMEOUT
 *     40 - BAD_REQUEST
 *     50 - BAD_RESPONSE
 *     60 - SERVICE_NOT_FOUND
 *     70 - SERVICE_ERROR
 *     80 - SERVER_ERROR
 *     90 - CLIENT_ERROR
 *     100 - SERVER_THREADPOOL_EXHAUSTED_ERROR
 * - Request ID (64 bits) 标识唯一请求。类型为long。
 * - Data Length (32 bits) 序列化后的内容长度（可变部分），按字节计数。int类型。
 * - Variable Part
 *     被特定的序列化类型（由序列化 ID 标识）序列化后，每个部分都是一个 byte [] 或者 byte
 *     如果是请求包 ( Req/Res = 1)，则每个部分依次为：
 *         Dubbo version
 *         Service name
 *         Service version
 *         Method name
 *         Method parameter types
 *         Method arguments
 *         Attachments
 *     如果是响应包（Req/Res = 0），则每个部分依次为：
 *         返回值类型(byte)，标识从服务器端返回的值类型：
 *             返回空值：RESPONSE_NULL_VALUE 2
 *             正常响应值： RESPONSE_VALUE 1
 *             异常：RESPONSE_WITH_EXCEPTION 0
 * 返回值：从服务端返回的响应bytes
 *
 * 包数据=dubbo版本号+接口名称+接口版本号+方法名+参数类型+参数值+ attachments
 */
struct dubbo_header {
	__u16 magic;
	__u8 serial_id:5;
	__u8 event:1;
	__u8 to_way:1;
	__u8 is_req:1;
	__u8 status;
	__u64 request_id;
	__u32 data_len;
} __attribute__ ((packed));

static __inline enum message_type infer_dubbo_message(const char *buf,
						      size_t count,
						      struct conn_info_t
						      *conn_info)
{
	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_DUBBO)
			return MSG_UNKNOWN;
	}
	// dubbo_header 大小是16字节，如果接收数量比16字节小直接返回。
	if (count < 16) {
		return MSG_UNKNOWN;
	}

	struct dubbo_header *dubbo_hdr = (struct dubbo_header *)buf;
	if (dubbo_hdr->magic != 0xbbda)
		return MSG_UNKNOWN;

	if (dubbo_hdr->serial_id < 2 || dubbo_hdr->serial_id == 5 ||
	    (dubbo_hdr->serial_id > 12 && dubbo_hdr->serial_id < 16))
		return MSG_UNKNOWN;

	if (dubbo_hdr->event == 1 && __bpf_ntohl(dubbo_hdr->data_len) != 1)
		return MSG_UNKNOWN;

	if (dubbo_hdr->is_req == 1) {
		return MSG_REQUEST;
	}

	return MSG_RESPONSE;
}

/*
 * Reference: https://kafka.apache.org/protocol.html#protocol_messages
 * 1、长度：
 * -----------------------------------------------------------------
 * RequestOrResponse --> Size( RequestMessage | ResponseMessage )
 *    Size --> int32
 * -----------------------------------------------------------------
 * 说明：解析时应先读取4字节的长度N，然后读取并解析后续的N字节请求/响应内容。
 *
 * 2、请求都具有以下格式：
 * ------------------------------------------------------------------
 * RequestMessage --> request_header request
 *   request_header --> api_key api_version correlation_id client_id
 *       api_key --> int16
 *       api_version --> int16
 *       correlation_id -->int32
 *       client_id --> string
 *   request --> MetadataRequest | ProduceRequest | FetchRequest | ...
 * -------------------------------------------------------------------
 * 说明：
 * request_header：同类型的请求有不同的ID [0, 67]
 * correlation_id：用户提供的整数，它将被服务器原封不动的传回给客户端,
 *                 用于匹配客户端和服务器之间的请求和响应。
 *
 *
 * 3、响应都具有以下格式：
 * -------------------------------------------------------------------
 * ResponseMessage --> response_header response
 *   response_header --> correlation_id
 *       correlation_id --> int32
 *   response --> MetadataResponse | ProduceResponse | ...
 * -------------------------------------------------------------------
 * 说明：correlation_id 即请求中携带的correlation_id
 *
 * 下面信息依据kafka原文件./clients/src/main/resources/common/message/目录下各种Request.json
 * ProduceRequest : apiKey 0, validVersions "0-9"
 * FetchRequest : apiKey 1, validVersions "0-13"
 * ListOffsetsRequest : apiKey 2, validVersions "0-7"
 * MetadataRequest: apiKey 3, validVersions "0-12",
 * HeartbeatRddequest: "apiKey": 12, "type": "request", "validVersions": "0-4"
 */
static __inline enum message_type infer_kafka_request(const char *buf,
						      bool is_first,
						      struct conn_info_t
						      *conn_info)
{
#define RequestAPIKeyMax 67
#define RequestAPIVerMax 13
#define ProduceRequest 0
#define FetchRequest   1
#define ListOffsetsRequest 2
#define MetadataRequest 3
#define HeartbeatRequest 12

	const __s16 request_api_key = __bpf_ntohs(*(__s16 *) buf);
	const __s16 request_api_version = __bpf_ntohs(*(__s16 *) (buf + 2));

	if (request_api_key < 0 || request_api_key > RequestAPIKeyMax)
		return MSG_UNKNOWN;

	if (request_api_version < 0 || request_api_version > RequestAPIVerMax)
		return MSG_UNKNOWN;

	switch (request_api_key) {
	case ProduceRequest:
		if (request_api_version > 9)
			return MSG_UNKNOWN;
		break;
	case FetchRequest:
		if (request_api_version > 13)
			return MSG_UNKNOWN;
		break;
	case ListOffsetsRequest:
		if (request_api_version > 7)
			return MSG_UNKNOWN;
		break;
	case MetadataRequest:
		if (request_api_version > 12)
			return MSG_UNKNOWN;
		break;
	case HeartbeatRequest:
		if (request_api_version > 4)
			return MSG_UNKNOWN;
		break;
	default:
		if (is_first)
			return MSG_UNKNOWN;
	}

	const __s32 correlation_id = __bpf_ntohl(*(__s32 *) (buf + 4));
	if (correlation_id < 0) {
		return MSG_UNKNOWN;
	}

	conn_info->correlation_id = (__u32) correlation_id;

	return MSG_REQUEST;
}

static __inline bool kafka_data_check_len(size_t count,
					  const char *buf,
					  struct conn_info_t *conn_info,
					  bool * use_prev_buf)
{
	*use_prev_buf = (conn_info->prev_count == 4)
	    && ((size_t) __bpf_ntohl(*(__s32 *) conn_info->prev_buf) == count);

	if (*use_prev_buf) {
		count += 4;
	}
	// length(4 bytes) + api_key(2 bytes) + api_version(2 bytes) + correlation_id(4 bytes)
	static const int min_req_len = 12;
	if (count < min_req_len) {
		return false;
	}
	// 总长度包含了length本身占用的4个字节
	const __s32 message_size =
	    *use_prev_buf ? count : __bpf_ntohl(*(__s32 *) buf) + 4;

	// Enforcing count to be exactly message_size + 4 to mitigate misclassification.
	// However, this will miss long messages broken into multiple reads.
	if (message_size < 0 || count != (size_t) message_size) {
		return false;
	}

	return true;
}

static __inline enum message_type infer_kafka_message(const char *buf,
						      size_t count,
						      struct conn_info_t
						      *conn_info)
{
	bool is_first = true, use_prev_buf;
	if (!kafka_data_check_len(count, buf, conn_info, &use_prev_buf))
		return MSG_UNKNOWN;

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_KAFKA)
			return MSG_UNKNOWN;

		conn_info->need_reconfirm =
		    conn_info->socket_info_ptr->need_reconfirm;

		if (!conn_info->need_reconfirm) {
			if ((conn_info->role == ROLE_CLIENT
			     && conn_info->direction == T_EGRESS)
			    || (conn_info->role == ROLE_SERVER
				&& conn_info->direction == T_INGRESS)) {
				return MSG_REQUEST;
			}

			return MSG_RESPONSE;
		}

		conn_info->correlation_id =
		    conn_info->socket_info_ptr->correlation_id;
		conn_info->role = conn_info->socket_info_ptr->role;
		is_first = false;
	} else
		conn_info->need_reconfirm = true;

	const char *msg_buf = use_prev_buf ? buf : buf + 4;
	enum message_type msg_type =
	    infer_kafka_request(msg_buf, is_first, conn_info);
	if (msg_type == MSG_REQUEST) {
		// 首次需要在socket_info_map新建socket
		if (is_first) {
			return MSG_RECONFIRM;
		}

		/*
		 * socket_info_map已经存在并且需要确认（需要response的数据进一步），
		 * 这里的request的数据直接丢弃。
		 */
		return MSG_UNKNOWN;
	}
	// 推断的第一个包必须是请求包，否则直接丢弃
	if (is_first)
		return MSG_UNKNOWN;

	// is response ?
	// Response Header v0 => correlation_id
	//  correlation_id => INT32
	const __s32 correlation_id = __bpf_ntohl(*(__s32 *) msg_buf);
	if (correlation_id < 0)
		return MSG_UNKNOWN;

	if (correlation_id == conn_info->correlation_id) {
		// 完成确认
		if (is_socket_info_valid(conn_info->socket_info_ptr)) {
			conn_info->socket_info_ptr->need_reconfirm = false;
			// 角色确认
			if (conn_info->direction == T_EGRESS)
				conn_info->socket_info_ptr->role = ROLE_SERVER;
			else
				conn_info->socket_info_ptr->role = ROLE_CLIENT;
		}
	} else {
		// 再次确认失败直接删除socket记录。
		return MSG_CLEAR;
	}

	// kafka长连接的形式存在，数据开始捕获从类型推断完成开始进行。
	// 此处数据（用于确认协议类型）丢弃不要，避免发给用户产生混乱。
	return MSG_UNKNOWN;
}

static __inline bool is_same_command(char *a, char *b)
{
	const int KERNEL_COMM_MAX = 16;
	for (int idx = 0; idx < KERNEL_COMM_MAX; ++idx) {
		if (a[idx] == '\0' && a[idx] == b[idx])
			return true;

		if (a[idx] != b[idx])
			return false;
	}
	// 16个字符都相同,并且没有遇到'\0',理论上不应该执行到这里
	return true;
}

static __inline bool drop_msg_by_comm(void)
{
	char comm[16];

	if (bpf_get_current_comm(&comm, sizeof(comm)))
		return false;

	if (is_same_command("sshd", comm))
		return true;

	if (is_same_command("ssh", comm))
		return true;

	if (is_same_command("scp", comm))
		return true;

	return false;
}

static __inline struct protocol_message_t infer_protocol(const char *buf,
							 size_t count,
							 struct conn_info_t
							 *conn_info,
							 __u8 sk_state)
{
#define DATA_BUF_MAX  32

	struct protocol_message_t inferred_message;
	inferred_message.protocol = PROTO_UNKNOWN;
	inferred_message.type = MSG_UNKNOWN;

	if (conn_info->sk_type == SOCK_STREAM &&
	    sk_state != SOCK_CHECK_TYPE_TCP_ES)
		return inferred_message;

	if (conn_info->tuple.dport == 0 || conn_info->tuple.num == 0) {
		return inferred_message;
	}

	if (count < 4 || conn_info->sk == NULL)
		return inferred_message;

	// 明确被判定了协议的socket不进入drop_msg_by_comm
	if (!is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (drop_msg_by_comm())
			return inferred_message;
	}

	char infer_buf[DATA_BUF_MAX];
	bpf_probe_read(&infer_buf, sizeof(infer_buf), buf);

	/*
	 * 为了提高协议推断的准确率，做了一下处理：
	 *
	 * 数据一旦首次被推断成功，就会把推断的L7协议类型设置到socket上，这样
	 * 凡是通过此socket读写的所有数据，协议类型就已经被确定了。
	 * 协议推断程序可以快速判断是否要进行数据推断处理。
	 * 例如：
	 *   在 infer_http_message() 中可以快速通过
	 *      if (conn_info->socket_info_ptr->l7_proto != PROTO_HTTP1)
	 *              return MSG_UNKNOWN;
	 *     ... ...
	 *   进行快速判断。
	 */

	if ((inferred_message.type =
	     infer_http_message(infer_buf, count, conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_HTTP1;
	} else if ((inferred_message.type =
		    infer_redis_message(infer_buf, count,
					conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_REDIS;
	} else if ((inferred_message.type =
		    infer_dubbo_message(infer_buf, count,
					conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_DUBBO;
	} else if ((inferred_message.type =
		    infer_dns_message(infer_buf, count,
				      conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_DNS;
	}

	if (inferred_message.protocol != MSG_UNKNOWN)
		return inferred_message;

	if (count == 4) {
		if (is_socket_info_valid(conn_info->socket_info_ptr)) {
			*(__u32 *) conn_info->socket_info_ptr->prev_data =
			    *(__u32 *) infer_buf;
			conn_info->socket_info_ptr->prev_data_len = 4;
			conn_info->socket_info_ptr->direction =
			    conn_info->direction;
		} else {
			*(__u32 *) conn_info->prev_buf = *(__u32 *) infer_buf;
			conn_info->prev_count = 4;
		}

		inferred_message.type = MSG_PRESTORE;
		return inferred_message;
	}
	// MySQL、Kafka推断需要之前的4字节数据
	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->prev_data_len != 0) {
			if (conn_info->direction !=
			    conn_info->socket_info_ptr->direction)
				return inferred_message;

			*(__u32 *) conn_info->prev_buf =
			    *(__u32 *) conn_info->socket_info_ptr->prev_data;
			conn_info->prev_count = 4;

			/*
			 * 上次存储的数据清忽略掉
			 */
			conn_info->socket_info_ptr->prev_data_len = 0;
		}
	}

	if ((inferred_message.type =
	     infer_http2_message(buf, count, conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_HTTP2;
	} else if ((inferred_message.type =
		    infer_mysql_message(infer_buf, count,
					conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_MYSQL;
	} else if ((inferred_message.type =
		    infer_kafka_message(infer_buf, count,
					conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_KAFKA;
	}

	return inferred_message;
}

#endif /* __BPF_PROTO_INFER_H__ */
