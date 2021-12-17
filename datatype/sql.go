package datatype

import (
	"fmt"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
)

var mysqlInfoPool = pool.NewLockFreePool(func() interface{} {
	return new(MysqlInfo)
})

func AcquireMYSQLInfo() *MysqlInfo {
	return mysqlInfoPool.Get().(*MysqlInfo)
}

func ReleaseMYSQLInfo(d *MysqlInfo) {
	*d = MysqlInfo{}
	mysqlInfoPool.Put(d)
}

const (
	MYSQL_COMMAND_QUIT = iota + 1
	MYSQL_COMMAND_USE_DATABASE
	MYSQL_COMMAND_QUERY
	MYSQL_COMMAND_SHOW_FIELD
	MYSQL_COMMAND_MAX
)

const (
	MYSQL_RESPONSE_CODE_OK  = 0
	MYSQL_RESPONSE_CODE_ERR = 0xff
	MYSQL_RESPONSE_CODE_EOF = 0xfe
)

type MysqlInfo struct {
	// Server Greeting
	ProtocolVersion uint8
	ServerVersion   string
	ServerThreadID  uint32
	// Request
	Command uint8
	Context string
	// Response
	ResponseCode uint8
	AffectedRows uint8
	ErrorCode    uint16
	ErrorMessage string
}

func (i *MysqlInfo) Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16) {
	switch msgType {
	case MSG_T_OTHER:
		encoder.WriteU8(i.ProtocolVersion)
		encoder.WriteString255(i.ServerVersion)
		encoder.WriteU32(i.ServerThreadID)
	case MSG_T_REQUEST:
		encoder.WriteU8(i.Command)
		encoder.WriteString255(i.Context)
	case MSG_T_RESPONSE:
		encoder.WriteU8(i.ResponseCode)
		encoder.WriteU8(i.AffectedRows)
		encoder.WriteU16(i.ErrorCode)
		encoder.WriteString255(i.ErrorMessage)
	case MSG_T_SESSION:
		encoder.WriteU8(i.Command)
		encoder.WriteString255(i.Context)

		encoder.WriteU8(i.ResponseCode)
		encoder.WriteU8(i.AffectedRows)
		encoder.WriteU16(i.ErrorCode)
		encoder.WriteString255(i.ErrorMessage)
	}
}

func (i *MysqlInfo) Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16) {
	switch msgType {
	case MSG_T_OTHER:
		i.ProtocolVersion = decoder.ReadU8()
		i.ServerVersion = decoder.ReadString255()
		i.ServerThreadID = decoder.ReadU32()
	case MSG_T_REQUEST:
		i.Command = decoder.ReadU8()
		i.Context = decoder.ReadString255()
	case MSG_T_RESPONSE:
		i.ResponseCode = decoder.ReadU8()
		i.AffectedRows = decoder.ReadU8()
		i.ErrorCode = decoder.ReadU16()
		i.ErrorMessage = decoder.ReadString255()
	case MSG_T_SESSION:
		i.Command = decoder.ReadU8()
		i.Context = decoder.ReadString255()

		i.ResponseCode = decoder.ReadU8()
		i.AffectedRows = decoder.ReadU8()
		i.ErrorCode = decoder.ReadU16()
		i.ErrorMessage = decoder.ReadString255()
	}
}

func (i *MysqlInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func (i *MysqlInfo) Merge(r interface{}) {
	if response, ok := r.(*MysqlInfo); ok {
		i.ResponseCode = response.ResponseCode
		i.AffectedRows = response.AffectedRows
		i.ErrorCode = response.ErrorCode
	}
}

var redisInfoPool = pool.NewLockFreePool(func() interface{} {
	return new(RedisInfo)
})

func AcquireREDISInfo() *RedisInfo {
	return redisInfoPool.Get().(*RedisInfo)
}

func ReleaseREDISInfo(d *RedisInfo) {
	*d = RedisInfo{}
	redisInfoPool.Put(d)
}

type RedisInfo struct {
	Request     string // 命令字段包括参数例如："set key value"
	RequestType string // 命令类型不包括参数例如：命令为"set key value"，命令类型为："set"

	Response string // 整数回复 + 批量回复 + 多条批量回复
	Status   string // '+'
	Error    string // '-'
}

func (i *RedisInfo) Encode(encoder *codec.SimpleEncoder, msgType LogMessageType, code uint16) {
	switch msgType {
	case MSG_T_REQUEST:
		encoder.WriteString255(i.Request)
		encoder.WriteString255(i.RequestType)
	case MSG_T_RESPONSE:
		encoder.WriteString255(i.Response)
		encoder.WriteString255(i.Status)
		encoder.WriteString255(i.Error)
	case MSG_T_SESSION:
		encoder.WriteString255(i.Request)
		encoder.WriteString255(i.RequestType)
		encoder.WriteString255(i.Response)
		encoder.WriteString255(i.Status)
		encoder.WriteString255(i.Error)
	default:
		panic("RedisInfo encode msg type error!")

	}
}

func (i *RedisInfo) Decode(decoder *codec.SimpleDecoder, msgType LogMessageType, code uint16) {
	switch msgType {
	case MSG_T_REQUEST:
		i.Request = decoder.ReadString255()
		i.RequestType = decoder.ReadString255()
	case MSG_T_RESPONSE:
		i.Response = decoder.ReadString255()
		i.Status = decoder.ReadString255()
		i.Error = decoder.ReadString255()
	case MSG_T_SESSION:
		i.Request = decoder.ReadString255()
		i.RequestType = decoder.ReadString255()
		i.Response = decoder.ReadString255()
		i.Status = decoder.ReadString255()
		i.Error = decoder.ReadString255()
	default:
		panic("RedisInfo decode msg type error!")
	}
}

func (i *RedisInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func (i *RedisInfo) Merge(r interface{}) {
	if redis, ok := r.(*RedisInfo); ok {
		i.Response = redis.Response
	}
}
