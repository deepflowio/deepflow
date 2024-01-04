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

#ifndef SO_PLUGIN_C
#define SO_PLUGIN_C

#define EBPF_TYPE_TRACEPOINT 0
#define EBPF_TYPE_TLS_UPROBE 1
#define EBPF_TYPE_NONE 255

#define DIRECTION_C_TO_S 0
#define DIRECTION_S_TO_C 1

#define RESP_STATUS_OK 0
#define RESP_STATUS_NOT_EXIST 2
#define RESP_STATUS_SERV_ERR 3
#define RESP_STATUS_CLIENT_ERR 4

#define RESP_CODE_NULL -32768

#define MSG_TYPE_REQ 0
#define MSG_TYPE_RESP 1

#define ACTION_ERROR 0
#define ACTION_CONTINUE 1
#define ACTION_OK 2

// reference src/plugin/c_ffi.rs struct ParseCtx 
struct parse_ctx {
    unsigned char ip_type; // 4 or 6
    unsigned char ip_src[16];
    unsigned char ip_dst[16];
    unsigned short port_src;
    unsigned short port_dst;
    unsigned char l4_protocol; // 6 and 17 indicate tcp and udp
    // proto is return from on_check_payload, when on_check_paylaod, it set
    // to 0, other wise will set to non zero value
    unsigned char proto;
    unsigned char ebpf_type;
    unsigned long long time;
    unsigned char direction;
    unsigned char *process_kname;
    // the config of `l7_log_packet_size`
    int buf_size;
    int payload_size;
    /*
        paylaod is from the payload: &[u8] in
        L7ProtocolParserInterface::check_payload() and
        L7ProtocolParserInterface::parse_payload(), it can not modify and
        drop.
    */
    unsigned char *payload;
};

// reference src/plugin/c_ffi.rs struct Request 
struct request {
    unsigned char req_type[64];
    unsigned char domain[128];
    unsigned char resource[128];
    unsigned char endpoint[128];
};


// reference src/plugin/c_ffi.rs struct Response 
struct response {
    unsigned char status;
    int code;
    unsigned char exception[128];
    unsigned char result[512];
};

// reference src/plugin/c_ffi.rs struct TraceInfo 
struct trace_info {
    unsigned char trace_id[128];
    unsigned char span_id[128];
    unsigned char parent_span_id[128];
};

// reference src/plugin/c_ffi.rs struct ParseInfo 
struct parse_info {
    unsigned char msg_type;
    int req_len;
    int resp_len;
    char has_request_id;
    unsigned int request_id;
    struct trace_info trace;
    union {
        struct request req;
        struct response resp;
    } req_resp;
    unsigned int attr_len;
    // format: repeated (${key bytes}\0${val bytes}\0)
    char attributes[6144];
};

// reference src/plugin/c_ffi.rs struct CheckResult 
struct check_result {
    unsigned char proto;
    unsigned char proto_name[16];
};

// reference src/plugin/c_ffi.rs struct ParseResult 
struct parse_result {
    unsigned char action;
    int len;
};

/*
pub type CheckPayloadCFunc = extern "C" fn(*const ParseCtx) -> CheckResult;

pub type ParsePaylaodCFunc =
    extern "C" fn(*const ParseCtx, *mut ParseInfo, info_max_len: u16) ->
ParseResult;
*/
struct check_result on_check_payload(struct parse_ctx *ctx);
struct parse_result on_parse_payload(struct parse_ctx *ctx,
                                     struct parse_info *infos, int infos_len);

// invoke after dlopen, only call once
void init();

#endif
