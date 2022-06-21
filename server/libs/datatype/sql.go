package datatype

import (
	"fmt"

	"gitlab.yunshan.net/yunshan/droplet-libs/datatype/pb"
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
	ErrorCode    uint16
	AffectedRows uint64
	ErrorMessage string
}

func (i *MysqlInfo) WriteToPB(p *pb.MysqlInfo, msgType LogMessageType) {
	switch msgType {
	case MSG_T_OTHER:
		*p = pb.MysqlInfo{}
		p.ProtocolVersion = uint32(i.ProtocolVersion)
		p.ServerVersion = i.ServerVersion
		p.ServerThreadID = i.ServerThreadID
	case MSG_T_REQUEST:
		*p = pb.MysqlInfo{}
		p.Command = uint32(i.Command)
		p.Context = i.Context
	case MSG_T_RESPONSE:
		p.ResponseCode = uint32(i.ResponseCode)
		p.AffectedRows = i.AffectedRows
		p.ErrorCode = uint32(i.ErrorCode)
		p.ErrorMessage = i.ErrorMessage

		p.Command = 0
		p.Context = ""
		p.ProtocolVersion = 0
	case MSG_T_SESSION:
		p.Command = uint32(i.Command)
		p.Context = i.Context

		p.ResponseCode = uint32(i.ResponseCode)
		p.AffectedRows = i.AffectedRows
		p.ErrorCode = uint32(i.ErrorCode)
		p.ErrorMessage = i.ErrorMessage

		p.ProtocolVersion = 0
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
		i.ErrorMessage = response.ErrorMessage
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

func (i *RedisInfo) WriteToPB(p *pb.RedisInfo, msgType LogMessageType) {
	switch msgType {
	case MSG_T_REQUEST:
		p.Request = i.Request
		p.RequestType = i.RequestType

		p.Response = ""
		p.Status = ""
		p.Error = ""
	case MSG_T_RESPONSE:
		p.Request = ""
		p.RequestType = ""

		p.Response = i.Response
		p.Status = i.Status
		p.Error = i.Error
	case MSG_T_SESSION:
		p.Request = i.Request
		p.RequestType = i.RequestType
		p.Response = i.Response
		p.Status = i.Status
		p.Error = i.Error
	default:
		panic("RedisInfo encode msg type error!")
	}

}

func (i *RedisInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func (i *RedisInfo) Merge(r interface{}) {
	if redis, ok := r.(*RedisInfo); ok {
		i.Response = redis.Response
		i.Status = redis.Status
		i.Error = redis.Error
	}
}
