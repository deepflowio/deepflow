/*
 * Copyright (c) 2023 Yunshan Networks
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

package datatype

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/deepflowio/deepflow/server/libs/datatype/pb"
	"github.com/deepflowio/deepflow/server/libs/pool"
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
	COM_QUIT = iota + 1
	COM_INIT_DB
	COM_QUERY
	COM_FIELD_LIST
	COM_STMT_PREPARE = 22
	COM_STMT_EXECUTE = 23
	COM_STMT_CLOSE   = 25
	COM_STMT_FETCH   = 28
	COM_MAX          = 29
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

func (i *MysqlInfo) WriteToPB(p *pb.AppProtoLogsData, msgType LogMessageType) {
	if msgType == MSG_T_REQUEST || msgType == MSG_T_SESSION {
		p.Req = &pb.L7Request{
			ReqType:  MysqlCommand(i.Command).String(),
			Resource: i.Context,
		}
	}

	p.ReqLen, p.RespLen = -1, -1
	if msgType == MSG_T_RESPONSE || msgType == MSG_T_SESSION {
		p.Resp.Code = int32(i.ErrorCode)
		p.Resp.Exception = i.ErrorMessage
		if p.Resp.Code == 0 {
			p.Resp.Code = L7PROTOCOL_LOG_RESP_CODE_NONE
		}
	}
	p.RowEffect = uint32(i.AffectedRows)
}

func (i *MysqlInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func TrimCommand(sql string, commandMaxLength int) string {
	index := 0
	if len(sql) > 2 && sql[:2] == "/*" {
		index = strings.LastIndex(sql, "*/")
		if index < 0 {
			return ""
		}
		index += 2
	}
	subSql := sql[index:]
	i := 0
	start := -1
	for ; i < commandMaxLength && i < len(subSql); i++ {
		if start == -1 && subSql[i] == ' ' {
			commandMaxLength += 1
			continue
		}
		if !unicode.IsLetter(rune(subSql[i])) {
			if start == -1 {
				return ""
			}
			return strings.ToUpper(subSql[start:i])
		}
		if start == -1 {
			start = i
		}
	}
	return strings.ToUpper(subSql[start:i])
}

func (i *MysqlInfo) Merge(r interface{}) {
	if response, ok := r.(*MysqlInfo); ok {
		i.ResponseCode = response.ResponseCode
		if i.Command == COM_QUERY && len(i.Context) > 0 {
			command := TrimCommand(i.Context, 8)
			if command == "INSERT" || command == "UPDATE" || command == "DELETE" {
				i.AffectedRows = response.AffectedRows
			}
		}
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

func (i *RedisInfo) WriteToPB(p *pb.AppProtoLogsData, msgType LogMessageType) {
	if msgType == MSG_T_REQUEST || msgType == MSG_T_SESSION {
		p.Req = &pb.L7Request{
			ReqType:  i.RequestType,
			Resource: i.Request,
		}
	}

	p.ReqLen, p.RespLen = -1, -1
	if msgType == MSG_T_RESPONSE || msgType == MSG_T_SESSION {
		p.Resp.Result = i.Response
		p.Resp.Exception = i.Error
		if p.Resp.Code == 0 {
			p.Resp.Code = L7PROTOCOL_LOG_RESP_CODE_NONE
		}
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

var mongoInfoPool = pool.NewLockFreePool(func() interface{} {
	return new(MongoDBInfo)
})

func AcquireMONGOInfo() *MongoDBInfo {
	return mongoInfoPool.Get().(*MongoDBInfo)
}

func ReleaseMONGOInfo(d *MongoDBInfo) {
	*d = MongoDBInfo{}
	mongoInfoPool.Put(d)
}

type MongoDBInfo struct {
	// request
	MessageLength uint32
	RequestId     uint32
	ResponseTo    uint32
	OpCode        uint32
	OpCodeName    string
}

func (i *MongoDBInfo) WriteToPB(p *pb.AppProtoLogsData, msgType LogMessageType) {
	if msgType == MSG_T_REQUEST || msgType == MSG_T_SESSION {
		p.Req = &pb.L7Request{
			ReqType:  i.OpCodeName,
			Resource: strconv.FormatUint(uint64(i.RequestId), 10),
		}
		p.ReqLen = int32(i.MessageLength)
	}

	p.ReqLen, p.RespLen = -1, -1
	if msgType == MSG_T_RESPONSE || msgType == MSG_T_SESSION {
		p.Resp.Code = int32(i.OpCode)
		p.Resp.Exception = i.OpCodeName
		if p.Resp.Code == 0 {
			p.Resp.Code = L7PROTOCOL_LOG_RESP_CODE_NONE
		}
	}
	p.RowEffect = uint32(i.RequestId)
}

func (i *MongoDBInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func (i *MongoDBInfo) Merge(r interface{}) {
	if response, ok := r.(*MongoDBInfo); ok {
		i.MessageLength = response.MessageLength
		i.OpCode = response.OpCode
		i.RequestId = response.RequestId
		i.ResponseTo = response.ResponseTo
		i.OpCodeName = response.OpCodeName
	}
}
