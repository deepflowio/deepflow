package zerodoc

type MessageType uint8

const (
	MSG_FLOW_SECOND MessageType = iota
	MSG_FLOW
	MSG_GEO
	MSG_PACKET

	MSG_INVILID
)

const (
	MAX_STRING_LENGTH = 1024
)

const (
	FLOW_SECOND_ID uint8 = iota
	FLOW_ID
	GEO_ID
	PACKET_ID

	MAX_APP_ID
)

var MeterVTAPNames [MAX_APP_ID]string = [MAX_APP_ID]string{
	"vtap_360",
	"vtap_360",
	"vtap_360_geo",
	"vtap_packet",
}

var MeterNamesToID map[string]uint8

func GetMeterID(name string) uint8 {
	// TODO: fix this: cannot produce FLOW_ID from "vtap_360"
	if id, exist := MeterNamesToID[name]; exist {
		return id
	}
	log.Errorf("can't get meter(%s) id", name)
	return MAX_APP_ID
}

const (
	MAIN uint8 = iota
	MINI
	MAIN_ISP
	MAIN_REGION
	MAIN_CAST_TYPE
	MAIN_TCP_FLAGS

	MAX_MEASUREMENT_ID
)

var MeasurementNames [MAX_MEASUREMENT_ID]string = [MAX_MEASUREMENT_ID]string{
	"main",
	"mini",
}

var MeasurementNamesToID map[string]uint8

func GetMeasurementID(name string) uint8 {
	if mid, exist := MeasurementNamesToID[name]; exist {
		return mid
	}
	log.Errorf("can't get measurement(%s) id", name)
	return MAX_MEASUREMENT_ID
}

func init() {
	MeterNamesToID = make(map[string]uint8)
	for id, name := range MeterVTAPNames {
		MeterNamesToID[name] = uint8(id)
	}

	MeasurementNamesToID = make(map[string]uint8)
	for id, name := range MeasurementNames {
		MeasurementNamesToID[name] = uint8(id)
	}
}
