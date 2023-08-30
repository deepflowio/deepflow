package common

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/google/uuid"
	"github.com/op/go-logging"
	"go.opentelemetry.io/collector/pdata/pcommon"
	rand2 "math/rand"
	"reflect"
	"strconv"
	"strings"
	"unsafe"
)

type ExportItem interface {
	Release()
}

const (
	UNKNOWN_DATA  = 0
	CBPF_NET_SPAN = uint32(1 << datatype.SIGNAL_SOURCE_PACKET)
	EBPF_SYS_SPAN = uint32(1 << datatype.SIGNAL_SOURCE_EBPF)
	OTEL_APP_SPAN = uint32(1 << datatype.SIGNAL_SOURCE_OTEL)
)

var exportedDataStringMap = map[string]uint32{
	"cbpf-net-span": CBPF_NET_SPAN,
	"ebpf-sys-span": EBPF_SYS_SPAN,
	"otel-app-span": OTEL_APP_SPAN,
}

var log = logging.MustGetLogger("flow_log.exporter.common")

func bitsToString(bits uint32, strMap map[string]uint32) string {
	ret := ""
	for k, v := range strMap {
		if bits&v != 0 {
			if len(ret) == 0 {
				ret = k
			} else {
				ret = ret + "," + k
			}
		}
	}
	return ret
}

func ExportedDataBitsToString(bits uint32) string {
	return bitsToString(bits, exportedDataStringMap)
}

func StringToExportedData(str string) uint32 {
	t, ok := exportedDataStringMap[str]
	if !ok {
		log.Warningf("unknown exporter data: %s", str)
		return UNKNOWN_DATA
	}
	return t
}

const (
	UNKNOWN_DATA_TYPE = 0

	SERVICE_INFO uint32 = 1 << iota
	TRACING_INFO
	NETWORK_LAYER
	FLOW_INFO
	CLIENT_UNIVERSAL_TAG
	SERVER_UNIVERSAL_TAG
	TUNNEL_INFO
	TRANSPORT_LAYER
	APPLICATION_LAYER
	CAPTURE_INFO
	CLIENT_CUSTOM_TAG
	SERVER_CUSTOM_TAG
	NATIVE_TAG
	METRICS
	K8S_LABEL
)

var exportedDataTypeStringMap = map[string]uint32{
	"service_info":         SERVICE_INFO,
	"tracing_info":         TRACING_INFO,
	"network_layer":        NETWORK_LAYER,
	"flow_info":            FLOW_INFO,
	"client_universal_tag": CLIENT_UNIVERSAL_TAG,
	"server_universal_tag": SERVER_UNIVERSAL_TAG,
	"tunnel_info":          TUNNEL_INFO,
	"transport_layer":      TRANSPORT_LAYER,
	"application_layer":    APPLICATION_LAYER,
	"capture_info":         CAPTURE_INFO,
	"client_custom_tag":    CLIENT_CUSTOM_TAG,
	"server_custom_tag":    SERVER_CUSTOM_TAG,
	"native_tag":           NATIVE_TAG,
	"metrics":              METRICS,
	"k8s_label":            K8S_LABEL,
}

func StringToExportedDataType(str string) uint32 {
	t, ok := exportedDataTypeStringMap[str]
	if !ok {
		log.Warningf("unknown exporter data type: %s", str)
		return UNKNOWN_DATA_TYPE
	}
	return t
}

func ExportedDataTypeBitsToString(bits uint32) string {
	return bitsToString(bits, exportedDataTypeStringMap)
}

// Extract the database, table, and command from the SQL statement to form SpanName("${comman} ${db}.${table}")
// Returns "unknown","" if it cannot be fetched.
func GetSQLSpanNameAndOperation(sql string) (string, string) {
	sql = strings.TrimSpace(sql)
	if sql == "" {
		return "unknow", ""
	}
	parts := strings.Split(sql, " ")
	if len(parts) <= 2 {
		return parts[0], parts[0]
	}

	var command, dbTable string
	command = parts[0]
	parts = parts[1:]
	switch strings.ToUpper(command) {
	case "SELECT", "DELETE":
		dbTable = GetFirstPartAfterKey("FROM", parts)
	case "INSERT":
		dbTable = GetFirstPartAfterKey("INTO", parts)
	case "UPDATE":
		dbTable = parts[0]
	case "CREATE", "DROP":
		createType := strings.ToUpper(parts[0])
		if createType == "DATABASE" || createType == "TABLE" {
			// ignore 'if not exists' or 'if exists'
			if strings.ToUpper(parts[1]) == "IF" {
				dbTable = GetFirstPartAfterKey("EXISTS", parts)
			} else {
				dbTable = parts[1]
			}
		}
	case "ALTER":
		dbTable = GetFirstPartAfterKey("TABLE", parts)
	}

	if dbTable == "" {
		return command, command
	}
	if i := strings.Index(dbTable, "("); i > 0 {
		dbTable = dbTable[:i]
	} else {
		dbTable = strings.TrimRight(dbTable, ";")
	}
	return strings.Join([]string{command, dbTable}, " "), command
}

// Return the first part after 'key' from the 'parts' array.
// Returns an empty string if 'key' does not exist or has no next part.
func GetFirstPartAfterKey(key string, parts []string) string {
	for i := range parts {
		if strings.ToUpper(parts[i]) == key && len(parts) > i+1 {
			return parts[i+1]
		}
	}
	return ""
}

type Counter struct {
	RecvCounter          int64 `statsd:"recv-count"`
	SendCounter          int64 `statsd:"send-count"`
	SendBatchCounter     int64 `statsd:"send-batch-count"`
	ExportUsedTimeNs     int64 `statsd:"export-used-time-ns"`
	DropCounter          int64 `statsd:"drop-count"`
	DropBatchCounter     int64 `statsd:"drop-batch-count"`
	DropNoTraceIDCounter int64 `statsd:"drop-no-traceid-count"`
}

func GetTraceID(traceID string, id uint64) pcommon.TraceID {
	if traceID == "" {
		return genTraceID(int(id))
	}

	if traceId, err := hex.DecodeString(traceID); err == nil {
		id := [16]byte{}
		copy(id[:], traceId)
		return pcommon.TraceID(id)
	}

	return swTraceIDToTraceID(traceID)
}

func GetSpanID(spanID string, id uint64) pcommon.SpanID {
	if spanID == "" {
		return Uint64ToSpanID(id)
	}

	if spanId, err := hex.DecodeString(spanID); err == nil {
		id := [8]byte{}
		copy(id[:], spanId)
		return pcommon.SpanID(id)
	}
	return pcommon.NewSpanIDEmpty()
}

func NewSpanId() pcommon.SpanID {
	var rngSeed int64
	_ = binary.Read(rand.Reader, binary.LittleEndian, &rngSeed)
	var randSource = rand2.New(rand2.NewSource(rngSeed))

	sid := pcommon.SpanID{}
	randSource.Read(sid[:])
	return sid
}

func genTraceID(id int) pcommon.TraceID {
	b := [16]byte{0}
	binary.BigEndian.PutUint64(b[:], uint64(id))
	return pcommon.TraceID(b)
}

// from https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/c247210d319a58665f1988e231a5c5fcfc9b8383/receiver/skywalkingreceiver/internal/trace/skywalkingproto_to_traces.go#L265
func swTraceIDToTraceID(traceID string) pcommon.TraceID {
	// skywalking traceid format:
	// de5980b8-fce3-4a37-aab9-b4ac3af7eedd: from browser/js-sdk/envoy/nginx-lua sdk/py-agent
	// 56a5e1c519ae4c76a2b8b11d92cead7f.12.16563474296430001: from java-agent

	if len(traceID) <= 36 { // 36: uuid length (rfc4122)
		uid, err := uuid.Parse(traceID)
		if err != nil {
			return pcommon.NewTraceIDEmpty()
		}
		return pcommon.TraceID(uid)
	}
	return swStringToUUID(traceID, 0)
}

func swStringToUUID(s string, extra uint32) (dst [16]byte) {
	// there are 2 possible formats for 's':
	// s format = 56a5e1c519ae4c76a2b8b11d92cead7f.0000000000.000000000000000000
	//            ^ start(length=32)               ^ mid(u32) ^ last(u64)
	// uid = UUID(start) XOR ([4]byte(extra) . [4]byte(uint32(mid)) . [8]byte(uint64(last)))

	// s format = 56a5e1c519ae4c76a2b8b11d92cead7f
	//            ^ start(length=32)
	// uid = UUID(start) XOR [4]byte(extra)

	if len(s) < 32 {
		return
	}

	t := unsafeGetBytes(s)
	var uid [16]byte
	_, err := hex.Decode(uid[:], t[:32])
	if err != nil {
		return uid
	}

	for i := 0; i < 4; i++ {
		uid[i] ^= byte(extra)
		extra >>= 8
	}

	if len(s) == 32 {
		return uid
	}

	index1 := bytes.IndexByte(t, '.')
	index2 := bytes.LastIndexByte(t, '.')
	if index1 != 32 || index2 < 0 {
		return
	}

	mid, err := strconv.Atoi(s[index1+1 : index2])
	if err != nil {
		return
	}

	last, err := strconv.Atoi(s[index2+1:])
	if err != nil {
		return
	}

	for i := 4; i < 8; i++ {
		uid[i] ^= byte(mid)
		mid >>= 8
	}

	for i := 8; i < 16; i++ {
		uid[i] ^= byte(last)
		last >>= 8
	}

	return uid
}

func uuidTo8Bytes(uuid [16]byte) [8]byte {
	// high bit XOR low bit
	var dst [8]byte
	for i := 0; i < 8; i++ {
		dst[i] = uuid[i] ^ uuid[i+8]
	}
	return dst
}

func unsafeGetBytes(s string) []byte {
	return (*[0x7fff0000]byte)(unsafe.Pointer(
		(*reflect.StringHeader)(unsafe.Pointer(&s)).Data),
	)[:len(s):len(s)]
}

func Uint64ToSpanID(id uint64) pcommon.SpanID {
	b := [8]byte{0}
	binary.BigEndian.PutUint64(b[:], uint64(id))
	return pcommon.SpanID(b)
}
