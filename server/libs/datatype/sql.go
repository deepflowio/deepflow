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

package datatype

import (
	"fmt"

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
