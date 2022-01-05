package jsonify

import (
	"fmt"
	"time"

	"gitlab.yunshan.net/yunshan/droplet-libs/ckdb"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype/pb"
	"gitlab.yunshan.net/yunshan/droplet-libs/grpc"
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
)

type SQLLogger struct {
	pool.ReferenceCount
	_id uint64

	L7Base

	*pb.AppProtoLogsData
	mysql *pb.MysqlInfo
}

func SQLLoggerColumns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	columns = append(columns, ckdb.NewColumn("_id", ckdb.UInt64).SetCodec(ckdb.CodecDoubleDelta))
	columns = append(columns, L7BaseColumns()...)
	columns = append(columns,
		ckdb.NewColumn("l7_protocol", ckdb.UInt8).SetComment("应用协议, 3: Mysql"),
		ckdb.NewColumn("type", ckdb.UInt8).SetComment("报文类型, 0: 请求, 1:回复, 2:会话"),

		ckdb.NewColumn("command", ckdb.LowCardinalityString).SetComment("命令类型"),
		ckdb.NewColumn("context", ckdb.String).SetComment("命令参数"),

		ckdb.NewColumn("status_code", ckdb.UInt8).SetComment("状态, 0: 正常, 1: 异常"),
		ckdb.NewColumn("answer_code", ckdb.UInt16Nullable).SetComment("响应码"),
		ckdb.NewColumn("exception_desc", ckdb.String).SetComment("异常描述"),

		ckdb.NewColumn("duration", ckdb.UInt64).SetComment("响应时延, 请求报文与第一个响应报文的时长(us)"), // us
		ckdb.NewColumn("affected_rows", ckdb.UInt64).SetComment("影响行数").SetIndex(ckdb.IndexNone),
	)
	return columns
}

func (s *SQLLogger) WriteBlock(block *ckdb.Block) error {
	if err := block.WriteUInt64(s._id); err != nil {
		return err
	}

	if err := s.L7Base.WriteBlock(block); err != nil {
		return nil
	}
	if s.mysql != nil {
		if err := block.WriteUInt8(uint8(datatype.L7_PROTOCOL_MYSQL)); err != nil {
			return err
		}
		msgType := datatype.LogMessageType(s.AppProtoLogsData.BaseInfo.Head.MsgType)
		if err := block.WriteUInt8(uint8(msgType)); err != nil {
			return err
		}

		// 请求时有效
		command := ""
		if msgType == datatype.MSG_T_REQUEST || msgType == datatype.MSG_T_SESSION {
			command = MysqlCommand(s.mysql.Command).String()
		}
		if err := block.WriteString(command); err != nil {
			return err
		}
		if err := block.WriteString(s.mysql.Context); err != nil {
			return err
		}

		// 响应时有效
		status := uint8(s.AppProtoLogsData.BaseInfo.Head.Status)
		if msgType == datatype.MSG_T_REQUEST {
			status = datatype.STATUS_NOT_EXIST
		}
		if err := block.WriteUInt8(status); err != nil {
			return err
		}

		errCode := uint16(s.mysql.ErrorCode)
		if status != datatype.STATUS_ERROR {
			if err := block.WriteUInt16Nullable(nil); err != nil {
				return err
			}
		} else {
			if err := block.WriteUInt16Nullable(&errCode); err != nil {
				return err
			}
		}
		if err := block.WriteString(s.mysql.ErrorMessage); err != nil {
			return err
		}

		if err := block.WriteUInt64(s.AppProtoLogsData.BaseInfo.Head.RRT / uint64(time.Microsecond)); err != nil {
			return err
		}

		if err := block.WriteUInt64(s.mysql.AffectedRows); err != nil {
			return err
		}
	}

	return nil
}

func (s *SQLLogger) Fill(l *pb.AppProtoLogsData, platformData *grpc.PlatformInfoTable) {
	s.L7Base.Fill(l, platformData)

	s.mysql = l.Mysql
}

func (s *SQLLogger) Release() {
	ReleaseSQLLogger(s)
}

func (s *SQLLogger) EndTime() time.Duration {
	return time.Duration(s.L7Base.EndTime) * time.Microsecond
}

func (s *SQLLogger) String() string {
	return fmt.Sprintf("SQL: %+v\n", *s)
}

var poolSQLLogger = pool.NewLockFreePool(func() interface{} {
	return new(SQLLogger)
})

func AcquireSQLLogger() *SQLLogger {
	l := poolSQLLogger.Get().(*SQLLogger)
	l.ReferenceCount.Reset()
	return l
}

func ReleaseSQLLogger(l *SQLLogger) {
	if l == nil {
		return
	}
	if l.SubReferenceCount() {
		return
	}
	if l.AppProtoLogsData != nil {
		l.AppProtoLogsData.Release()
	}
	*l = SQLLogger{}
	poolSQLLogger.Put(l)
}

var L7SQLCounter uint32

func ProtoLogToSQLLogger(l *pb.AppProtoLogsData, shardID int, platformData *grpc.PlatformInfoTable) interface{} {
	h := AcquireSQLLogger()
	h.AppProtoLogsData = l
	h._id = genID(uint32(l.BaseInfo.EndTime/uint64(time.Second)), &L7SQLCounter, shardID)
	h.Fill(l, platformData)
	return h
}
