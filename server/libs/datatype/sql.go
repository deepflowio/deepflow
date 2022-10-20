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

	"github.com/deepflowys/deepflow/server/libs/datatype/pb"
	"github.com/deepflowys/deepflow/server/libs/pool"
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
	/*
		switch msgType {
		case MSG_T_OTHER:
			*p = pb.MysqlInfo{}
			p.ProtocolVersion = uint32(i.ProtocolVersion)
			p.ServerVersion = i.ServerVersion
			p.ServerThreadId = i.ServerThreadID
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
	*/
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
	/*
		switch msgType {
		case MSG_T_REQUEST:
			p.Request = []byte(i.Request)
			p.RequestType = []byte(i.RequestType)

			p.Response = nil
			p.Status = nil
			p.Error = nil
		case MSG_T_RESPONSE:
			p.Request = nil
			p.RequestType = nil

			p.Response = []byte(i.Response)
			p.Status = []byte(i.Status)
			p.Error = []byte(i.Error)
		case MSG_T_SESSION:
			p.Request = []byte(i.Request)
			p.RequestType = []byte(i.RequestType)
			p.Response = []byte(i.Response)
			p.Status = []byte(i.Status)
			p.Error = []byte(i.Error)
		default:
			panic("RedisInfo encode msg type error!")
		}
	*/

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
