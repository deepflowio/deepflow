package jsonify

import (
	"fmt"
	"strings"
	"time"

	"gitlab.yunshan.net/yunshan/droplet-libs/ckdb"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	"gitlab.yunshan.net/yunshan/droplet-libs/grpc"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
)

type NoSQLLogger struct {
	pool.ReferenceCount
	_id uint64

	L7Base

	*datatype.AppProtoLogsData
	redis *datatype.RedisInfo
}

func NoSQLLoggerColumns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	columns = append(columns, ckdb.NewColumn("_id", ckdb.UInt64).SetCodec(ckdb.CodecDoubleDelta))
	columns = append(columns, L7BaseColumns()...)
	columns = append(columns,
		ckdb.NewColumn("l7_protocol", ckdb.UInt8).SetComment("应用协议, 4: Redis"),
		ckdb.NewColumn("type", ckdb.UInt8).SetComment("报文类型, 0: 请求, 1:回复, 2:会话"),

		ckdb.NewColumn("command", ckdb.LowCardinalityString).SetComment("命令类型"),
		ckdb.NewColumn("context", ckdb.String).SetComment("命令参数"),
		ckdb.NewColumn("status_code", ckdb.UInt8).SetComment("状态, 0: 正常, 1: 异常"),
		ckdb.NewColumn("exception_desc", ckdb.String).SetComment("异常描述"),

		ckdb.NewColumn("duration", ckdb.UInt64).SetComment("响应时延, 请求报文与第一个响应报文的时长(us)"),
	)
	return columns
}

func (s *NoSQLLogger) WriteBlock(block *ckdb.Block) error {
	if err := block.WriteUInt64(s._id); err != nil {
		return err
	}

	if err := s.L7Base.WriteBlock(block); err != nil {
		return nil
	}
	if s.redis != nil {
		if err := block.WriteUInt8(uint8(datatype.L7_PROTOCOL_REDIS)); err != nil {
			return err
		}
		msgType := s.AppProtoLogsData.AppProtoLogsBaseInfo.MsgType
		if err := block.WriteUInt8(uint8(msgType)); err != nil {
			return err
		}

		// command
		if err := block.WriteString(strings.ToUpper(s.redis.RequestType)); err != nil {
			return err
		}
		if err := block.WriteString(s.redis.Request); err != nil {
			return err
		}
		// status
		status := s.AppProtoLogsData.AppProtoLogsBaseInfo.Status
		if msgType == datatype.MSG_T_REQUEST {
			status = datatype.STATUS_NOT_EXIST
		}
		if err := block.WriteUInt8(status); err != nil {
			return err
		}

		if err := block.WriteString(s.redis.Error); err != nil {
			return err
		}
		if err := block.WriteUInt64(uint64(s.AppProtoLogsData.AppProtoLogsBaseInfo.RRT / time.Microsecond)); err != nil {
			return err
		}
	}

	return nil
}

func (s *NoSQLLogger) Fill(l *datatype.AppProtoLogsData, platformData *grpc.PlatformInfoTable) {
	s.L7Base.Fill(l, platformData)

	if l.Proto == datatype.PROTO_REDIS {
		if info, ok := l.Detail.(*datatype.RedisInfo); ok {
			s.redis = info
		}
	}
}

func (s *NoSQLLogger) Release() {
	ReleaseNoSQLLogger(s)
}

func (s *NoSQLLogger) EndTime() time.Duration {
	return time.Duration(s.L7Base.EndTime) * time.Microsecond
}

func (s *NoSQLLogger) String() string {
	return fmt.Sprintf("NoSQL: %+v\n", *s)
}

var poolNoSQLLogger = pool.NewLockFreePool(func() interface{} {
	return new(NoSQLLogger)
})

func AcquireNoSQLLogger() *NoSQLLogger {
	l := poolNoSQLLogger.Get().(*NoSQLLogger)
	l.ReferenceCount.Reset()
	return l
}

func ReleaseNoSQLLogger(l *NoSQLLogger) {
	if l == nil {
		return
	}
	if l.SubReferenceCount() {
		return
	}
	if l.AppProtoLogsData != nil {
		l.AppProtoLogsData.Release()
	}
	*l = NoSQLLogger{}
	poolNoSQLLogger.Put(l)
}

var L7NoSQLCounter uint32

func ProtoLogToNoSQLLogger(l *datatype.AppProtoLogsData, shardID int, platformData *grpc.PlatformInfoTable) interface{} {
	h := AcquireNoSQLLogger()
	l.AddReferenceCount()
	h.AppProtoLogsData = l
	h._id = genID(uint32(l.EndTime/time.Second), &L7NoSQLCounter, shardID)
	h.Fill(l, platformData)
	return h
}
