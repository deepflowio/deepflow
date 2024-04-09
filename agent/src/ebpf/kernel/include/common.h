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

#ifndef DF_BPF_COMMON_H
#define DF_BPF_COMMON_H

// 消息类型
enum message_type {
	MSG_UNKNOWN,
	// L7协议推断数据类型是请求
	MSG_REQUEST,
	// L7协议推断数据类型是回应
	MSG_RESPONSE,

	// HTTP2 request message end marker
	MSG_REQUEST_END,
	// HTTP2 response message end marker
	MSG_RESPONSE_END,

	// 无法推断协议类型，先在map中存储等下一次的数据
	// 获取后两者合并，再进行判断。主要场景用于MySQL，Kafka
	// 读数据的行为先读取4字节数据后再读取剩下的数据，要想进行
	// 正确的协议判断需要合并这两部分数据才可以。
	MSG_PRESTORE,
	// 对于l7的协议推断需要再确认逻辑。
	MSG_RECONFIRM,
	// 用于信息相关清理，一般用于socket信息清除
	MSG_CLEAR
};

// 数据流方向
enum traffic_direction {
	T_EGRESS,
	T_INGRESS,
};

// 数据协议
enum traffic_protocol {
	PROTO_UNKNOWN = 0,
	PROTO_ORTHER = 1,
	PROTO_HTTP1 = 20,
	PROTO_HTTP2 = 21,
	PROTO_TLS_HTTP1 = 22,
	PROTO_TLS_HTTP2 = 23,
	PROTO_DUBBO = 40,
	PROTO_SOFARPC = 43,
	PROTO_MYSQL = 60,
	PROTO_POSTGRESQL = 61,
	PROTO_REDIS = 80,
	PROTO_KAFKA = 100,
	PROTO_MQTT = 101,
	PROTO_DNS = 120,
	PROTO_NUM = 130
};

struct protocol_message_t {
	enum traffic_protocol protocol;
	enum message_type type;
};

enum {
	TASK_COMM_LEN = 16,
};

#ifndef EBPF_CACHE_SIZE
#define EBPF_CACHE_SIZE 8
#endif

#endif /* DF_BPF_COMMON_H */
