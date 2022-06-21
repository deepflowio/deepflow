#ifndef __BPF_COMMON_H__
#define __BPF_COMMON_H__

// 消息类型
enum message_type {
	MSG_UNKNOWN,
	// L7协议推断数据类型是请求
	MSG_REQUEST,
	// L7协议推断数据类型是回应
	MSG_RESPONSE,
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
	PROTO_DUBBO = 40,
	PROTO_MYSQL = 60,
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

#endif /* __BPF_COMMON_H__ */
