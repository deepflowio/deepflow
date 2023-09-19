/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2022- The Yunshan Networks Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
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
	PROTO_FASTCGI = 44,
	PROTO_MYSQL = 60,
	PROTO_POSTGRESQL = 61,
	PROTO_REDIS = 80,
	PROTO_MONGO = 81,
	PROTO_KAFKA = 100,
	PROTO_MQTT = 101,
	PROTO_DNS = 120,
	PROTO_NUM = 130
};

struct protocol_message_t {
	enum traffic_protocol protocol;
	enum message_type type;
};

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef EBPF_CACHE_SIZE
#define EBPF_CACHE_SIZE 8
#endif

#endif /* DF_BPF_COMMON_H */
