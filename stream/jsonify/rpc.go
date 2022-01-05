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

// RPC
type RPCLogger struct {
	pool.ReferenceCount
	_id uint64

	L7Base

	*pb.AppProtoLogsData
	dubbo *pb.DubboInfo
}

func RPCLoggerColumns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	columns = append(columns, ckdb.NewColumn("_id", ckdb.UInt64).SetCodec(ckdb.CodecDoubleDelta))
	columns = append(columns, L7BaseColumns()...)
	columns = append(columns,
		ckdb.NewColumn("l7_protocol", ckdb.UInt8).SetComment("应用协议, 5: Dubbo"),
		ckdb.NewColumn("version", ckdb.LowCardinalityString).SetComment("协议版本"),
		ckdb.NewColumn("type", ckdb.UInt8).SetComment("报文类型, 0: 请求, 1: 回复, 2: 会话"),
		ckdb.NewColumn("request_id", ckdb.UInt64).SetComment("请求ID"),
		ckdb.NewColumn("service_name", ckdb.String).SetComment("服务名称"),
		ckdb.NewColumn("method_name", ckdb.String).SetComment("方法名称"),
		ckdb.NewColumn("status_code", ckdb.UInt8).SetComment("状态, 0: 正常, 1: 异常"),
		ckdb.NewColumn("answer_code", ckdb.UInt16Nullable).SetComment("响应码"),
		ckdb.NewColumn("exception_desc", ckdb.LowCardinalityString).SetComment("异常描述"),

		ckdb.NewColumn("duration", ckdb.UInt64).SetComment("响应时延, 统计请求报文与第一个响应报文的时长(us)"), // us
	)
	return columns
}

func (s *RPCLogger) WriteBlock(block *ckdb.Block) error {
	if err := block.WriteUInt64(s._id); err != nil {
		return err
	}

	if err := s.L7Base.WriteBlock(block); err != nil {
		return nil
	}

	if s.dubbo != nil {
		if err := block.WriteUInt8(uint8(datatype.L7_PROTOCOL_DUBBO)); err != nil {
			return err
		}
		if err := block.WriteString(s.dubbo.DubboVersion); err != nil {
			return err
		}
		msgType := datatype.LogMessageType(s.AppProtoLogsData.BaseInfo.Head.MsgType)
		if err := block.WriteUInt8(uint8(msgType)); err != nil {
			return err
		}
		if err := block.WriteUInt64(uint64(s.dubbo.ID)); err != nil {
			return err
		}
		if err := block.WriteString(s.dubbo.ServiceName); err != nil {
			return err
		}
		if err := block.WriteString(s.dubbo.MethodName); err != nil {
			return err
		}

		status := uint8(s.AppProtoLogsData.BaseInfo.Head.Status)
		if msgType == datatype.MSG_T_REQUEST {
			status = datatype.STATUS_NOT_EXIST
		}
		if err := block.WriteUInt8(status); err != nil {
			return err
		}

		answerCode := uint16(s.AppProtoLogsData.BaseInfo.Head.Code)
		if msgType == datatype.MSG_T_REQUEST {
			if err := block.WriteUInt16Nullable(nil); err != nil {
				return err
			}
		} else {
			if err := block.WriteUInt16Nullable(&answerCode); err != nil {
				return err
			}
		}

		execptionDesc := ""
		if answerCode >= uint16(OK) && answerCode <= SERVER_THREADPOOL_EXHAUSTED_ERROR {
			execptionDesc = dubboExceptionDesc[answerCode]
		}
		if err := block.WriteString(execptionDesc); err != nil {
			return err
		}

		if err := block.WriteUInt64(s.AppProtoLogsData.BaseInfo.Head.RRT / uint64(time.Microsecond)); err != nil {
			return err
		}
	}

	return nil
}

func (s *RPCLogger) Fill(l *pb.AppProtoLogsData, platformData *grpc.PlatformInfoTable) {
	s.L7Base.Fill(l, platformData)
	s.dubbo = l.Dubbo
}

func (s *RPCLogger) Release() {
	ReleaseRPCLogger(s)
}

func (s *RPCLogger) EndTime() time.Duration {
	return time.Duration(s.L7Base.EndTime) * time.Microsecond
}

func (s *RPCLogger) String() string {
	return fmt.Sprintf("RPC: %+v\n", *s)
}

var poolRPCLogger = pool.NewLockFreePool(func() interface{} {
	return new(RPCLogger)
})

func AcquireRPCLogger() *RPCLogger {
	l := poolRPCLogger.Get().(*RPCLogger)
	l.ReferenceCount.Reset()
	return l
}

func ReleaseRPCLogger(l *RPCLogger) {
	if l == nil {
		return
	}
	if l.SubReferenceCount() {
		return
	}
	if l.AppProtoLogsData != nil {
		l.AppProtoLogsData.Release()
	}
	*l = RPCLogger{}
	poolRPCLogger.Put(l)
}

var L7RPCCounter uint32

func ProtoLogToRPCLogger(l *pb.AppProtoLogsData, shardID int, platformData *grpc.PlatformInfoTable) interface{} {
	h := AcquireRPCLogger()
	h.AppProtoLogsData = l
	h._id = genID(uint32(l.BaseInfo.EndTime/uint64(time.Second)), &L7RPCCounter, shardID)
	h.Fill(l, platformData)
	return h
}
